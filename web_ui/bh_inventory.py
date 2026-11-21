"""
BloodHound inventory for the linWinPwn Web Console.

Reads BloodHound collector output (zip, folder or loose json; bloodhound-python
legacy, SharpHound v3+ and CE layouts) and produces a DEFENSIVE report:
an inventory of the directory plus AD hygiene checks, each with the objects to
fix and a remediation note.

Scope on purpose: this module counts and describes. It does not compute attack
paths, does not rank objects by exploitability and does not reference any
offensive tooling. For attack path analysis, import the same data into
BloodHound CE.

Pure standard library.
"""
import json
import re
import time
import zipfile
from collections import defaultdict
from pathlib import Path

FILE_TYPES = {
    "users": "User", "groups": "Group", "computers": "Computer", "domains": "Domain",
    "gpos": "GPO", "ous": "OU", "containers": "Container",
    "certtemplates": "CertTemplate", "enterprisecas": "EnterpriseCA", "rootcas": "RootCA",
    "aiacas": "AIACA", "ntauthstores": "NTAuthStore", "issuancepolicies": "IssuancePolicy",
}

DAY = 86400
MAX_UNCOMPRESSED = 3 * 1024 ** 3

# Privileged groups tracked by RID or well-known SID, with why they matter.
PRIV_BY_RID = {
    "512": "Domain Admins", "519": "Enterprise Admins", "518": "Schema Admins",
    "520": "Group Policy Creator Owners", "521": "Read-only Domain Controllers",
    "516": "Domain Controllers",
}
PRIV_BY_WK = {
    "S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators", "S-1-5-32-569": "Cryptographic Operators",
}

UNSUPPORTED_OS = re.compile(
    r"windows (xp|vista|7\b|8\b|8\.1|2000|server 2003|server 2008|server 2012)|"
    r"\b(2003|2008|2012)\b", re.I)
WIN10 = re.compile(r"windows 10", re.I)
SECRET_IN_TEXT = re.compile(
    r"pass(word|wd|phrase)?\s*[:=]|pwd\s*[:=]|mot de passe|motdepasse|\bmdp\b|"
    r"kennwort|contrase[ñn]a|\bcreds?\b\s*[:=]", re.I)


def _sid_tail(oid):
    i = oid.find("S-1-")
    return oid[i:] if i >= 0 else oid


def _rid(oid):
    t = _sid_tail(oid)
    return t.rsplit("-", 1)[-1] if t.startswith("S-1-5-21-") else None


def _days_since(v):
    """BloodHound timestamps are unix epoch; 0 and -1 mean never."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    return int((time.time() - v) // DAY)


def _iter_json(paths):
    """Yield (filename, bytes) for every json inside the given files/dirs/zips."""
    total = 0
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix.lower() == ".json":
                    yield f.name, f.read_bytes()
                elif f.suffix.lower() == ".zip":
                    yield from _iter_json([f])
        elif p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as z:
                for info in z.infolist():
                    if info.is_dir() or not info.filename.lower().endswith(".json"):
                        continue
                    total += info.file_size
                    if total > MAX_UNCOMPRESSED:
                        raise ValueError("archive too large (over 3 GB uncompressed)")
                    yield Path(info.filename).name, z.read(info)
        elif p.suffix.lower() == ".json":
            yield p.name, p.read_bytes()


def _detect(name, obj):
    meta = obj.get("meta") if isinstance(obj, dict) else None
    if isinstance(meta, dict) and str(meta.get("type", "")).lower() in FILE_TYPES:
        return str(meta["type"]).lower()
    low = name.lower()
    for k in FILE_TYPES:
        if low.endswith(k + ".json"):
            return k
    if isinstance(obj, dict):
        for k in FILE_TYPES:
            if isinstance(obj.get(k), list):
                return k
    return None


class Inventory:
    def __init__(self, paths, label=""):
        t0 = time.time()
        self.label = label
        self.objects = {}            # id -> {type, name, props}
        self.member_of = defaultdict(set)   # member id -> {group id}
        self.members = defaultdict(set)     # group id -> {member id}
        self.links = defaultdict(set)       # GPO id -> {OU / domain ids it is linked to}
        self.files = []
        self.collected = None
        self.domains = {}
        self.trusts = []
        self._load(paths)
        self.checks = []
        self._analyse()
        self.seconds = round(time.time() - t0, 2)

    # ---------------- loading ----------------
    def _load(self, paths):
        for name, raw in _iter_json(paths):
            try:
                obj = json.loads(raw.decode("utf-8-sig"))
            except Exception:
                continue
            ftype = _detect(name, obj)
            if not ftype:
                continue
            data = obj.get("data")
            if data is None:
                data = obj.get(ftype, [])
            if not isinstance(data, list):
                continue
            meta = obj.get("meta") or {}
            when = meta.get("collectionDate") or meta.get("CollectionDate")
            if when and not self.collected:
                self.collected = when
            self.files.append({"name": name, "type": ftype, "count": len(data)})
            for o in data:
                if isinstance(o, dict):
                    self._object(ftype, o)
        if not self.objects:
            raise ValueError(
                "no BloodHound data found. Expected a collector zip or *_users.json, "
                "*_computers.json, *_groups.json ... files.")

    def _object(self, ftype, o):
        ntype = FILE_TYPES[ftype]
        raw = o.get("Properties") or {}
        props = {str(k).lower(): v for k, v in raw.items()}
        oid = o.get("ObjectIdentifier") or props.get("objectid") or o.get("ObjectSid")
        if not oid:
            return
        oid = str(oid).upper()
        self.objects[oid] = {"type": ntype, "name": props.get("name") or oid, "props": props}

        if ntype == "Domain":
            self.domains[oid] = props.get("name") or oid
            for t in o.get("Trusts") or []:
                self.trusts.append({
                    "domain": props.get("name") or oid,
                    "target": t.get("TargetDomainName") or t.get("TargetDomainSid"),
                    "direction": t.get("TrustDirection"),
                    "type": t.get("TrustType"),
                    "transitive": t.get("IsTransitive"),
                    "sidfiltering": t.get("SidFilteringEnabled"),
                })

        # group membership (needed to size privileged groups)
        if ntype == "Group":
            for m in o.get("Members") or []:
                mid = m.get("ObjectIdentifier") if isinstance(m, dict) else m
                if mid:
                    mid = str(mid).upper()
                    self.member_of[mid].add(oid)
                    self.members[oid].add(mid)
        pg = o.get("PrimaryGroupSID") or props.get("primarygroupsid")
        if pg:
            pg = str(pg).upper()
            self.member_of[oid].add(pg)
            self.members[pg].add(oid)
        # GPO links on OUs and domains (used to find unlinked GPOs)
        if ntype in ("OU", "Domain"):
            for l in o.get("Links") or []:
                gid = l.get("GUID") if isinstance(l, dict) else l
                if gid:
                    self.links[str(gid).upper()].add(oid)
        if o.get("HasSIDHistory"):
            props.setdefault("_sidhistory", [
                (h.get("ObjectIdentifier") if isinstance(h, dict) else h) for h in o["HasSIDHistory"]])

    # ---------------- helpers ----------------
    WELL_KNOWN_RID = {"500": "Administrator", "501": "Guest", "502": "krbtgt", "512": "Domain Admins",
                      "513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers",
                      "516": "Domain Controllers", "517": "Cert Publishers", "518": "Schema Admins",
                      "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
                      "521": "Read-only Domain Controllers", "525": "Protected Users", "526": "Key Admins",
                      "527": "Enterprise Key Admins", "553": "RAS and IAS Servers"}
    WELL_KNOWN_SID = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-7": "Anonymous Logon",
                      "S-1-5-9": "Enterprise Domain Controllers", "S-1-5-18": "Local System",
                      "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-548": "Account Operators",
                      "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
                      "S-1-5-32-551": "Backup Operators", "S-1-5-32-554": "Pre-Windows 2000 Compatible Access"}

    def name(self, oid):
        n = self.objects.get(oid)
        if n:
            return n["name"]
        r = _rid(oid)
        if r in self.WELL_KNOWN_RID:
            return self.WELL_KNOWN_RID[r] + " (not collected)"
        return self.WELL_KNOWN_SID.get(_sid_tail(oid), oid)

    def typ(self, oid):
        return (self.objects.get(oid) or {}).get("type", "Base")

    def prop(self, oid, key, default=None):
        return (self.objects.get(oid) or {}).get("props", {}).get(key, default)

    def enabled(self, oid):
        return self.prop(oid, "enabled") is not False

    def of_type(self, t, enabled_only=False):
        return [i for i, n in self.objects.items()
                if n["type"] == t and (not enabled_only or self.enabled(i))]

    def group_members(self, gid, types=None, _seen=None):
        """Recursive members of a group (used only to size privileged groups)."""
        seen = _seen if _seen is not None else set()
        out = set()
        for mid in self.members.get(gid, ()):
            if mid in seen:
                continue
            seen.add(mid)
            if self.typ(mid) == "Group":
                out |= self.group_members(mid, types, seen)
            elif not types or self.typ(mid) in types:
                out.add(mid)
        return out

    def find_groups(self):
        """Privileged groups present in the data -> {id: label}."""
        found = {}
        for oid in self.objects:
            if self.typ(oid) != "Group":
                continue
            label = PRIV_BY_RID.get(_rid(oid) or "") or PRIV_BY_WK.get(_sid_tail(oid))
            if label:
                found[oid] = label
        return found

    def add(self, cid, sev, title, items, why, fix, total=None):
        """Record a hygiene check. items: list of dicts or object ids."""
        rows = []
        for o in items[:500]:
            if isinstance(o, dict):
                rows.append(o)
            else:
                rows.append({"id": o, "name": self.name(o), "type": self.typ(o)})
        self.checks.append({
            "id": cid, "severity": sev, "title": title,
            "count": len(items), "total": total,
            "pct": (round(100 * len(items) / total) if total else None),
            "items": rows, "truncated": len(items) > len(rows),
            "why": why, "fix": fix,
        })

    # ---------------- checks ----------------
    def _analyse(self):
        users_all = self.of_type("User")
        users = self.of_type("User", True)
        comps_all = self.of_type("Computer")
        comps = self.of_type("Computer", True)
        nu, nc = len(users), len(comps)

        # --- account lifecycle -------------------------------------------------
        stale = []
        never = []
        for u in users:
            if self.name(u).upper().startswith(("KRBTGT@", "GUEST@")):
                continue
            d = _days_since(self.prop(u, "lastlogontimestamp"))
            if d is None:
                never.append({"id": u, "name": self.name(u), "type": "User",
                              "detail": "never logged on"})
            elif d > 90:
                stale.append({"id": u, "name": self.name(u), "type": "User",
                              "detail": f"last logon {d} days ago", "sort": d})
        stale.sort(key=lambda r: -r["sort"])
        if stale:
            self.add("stale", "medium", "Enabled accounts inactive for over 90 days", stale,
                     "Dormant but enabled accounts stay usable and nobody notices when they are. "
                     "They are the accounts most often forgotten in password rotations.",
                     "Disable them, then delete after a retention period. Automate with a scheduled review.", nu)
        if never:
            self.add("never", "medium", "Enabled accounts that never logged on", never,
                     "Accounts created and never used. Often test or service accounts left behind.",
                     "Confirm with the owner, then disable or delete.", nu)
        disabled = [u for u in users_all if not self.enabled(u)]
        if disabled:
            self.add("disabled", "info", "Disabled accounts", disabled,
                     "Normal to have some. Worth cleaning if the number keeps growing.",
                     "Delete after your retention period.", len(users_all))

        # --- password hygiene ---------------------------------------------------
        pne = [u for u in users if self.prop(u, "pwdneverexpires")]
        if pne:
            self.add("pwdneverexpires", "medium", "Passwords set to never expire", pne,
                     "A password that never changes stays valid for years, including after a leak "
                     "or after someone leaves.",
                     "Remove DONT_EXPIRE_PASSWORD. For service accounts, move to gMSA so Windows "
                     "rotates the password automatically.", nu)
        pnr = [u for u in users if self.prop(u, "passwordnotreqd")]
        if pnr:
            self.add("passwordnotreqd", "high", "Accounts that do not require a password", pnr,
                     "PASSWD_NOTREQD lets the account keep an empty password, whatever the domain policy says.",
                     "Clear the flag and set a password on each account.", nu)
        old_pw = []
        for u in users:
            if _rid(u) == "502":          # krbtgt has its own check below
                continue
            d = _days_since(self.prop(u, "pwdlastset"))
            if d is not None and d > 365:
                old_pw.append({"id": u, "name": self.name(u), "type": "User",
                               "detail": f"password set {d} days ago", "sort": d})
        old_pw.sort(key=lambda r: -r["sort"])
        if old_pw:
            self.add("oldpw", "medium", "Passwords older than one year", old_pw,
                     "Long-lived passwords are the ones that end up in breach dumps and in shared notes.",
                     "Rotate them and keep a maximum password age in the domain policy.", nu)

        # --- service accounts ----------------------------------------------------
        spn = [u for u in users if self.prop(u, "hasspn")
               and not self.name(u).upper().startswith("KRBTGT@")]
        if spn:
            rows = []
            for u in spn:
                d = _days_since(self.prop(u, "pwdlastset"))
                rows.append({"id": u, "name": self.name(u), "type": "User",
                             "detail": (f"password {d} days old" if d is not None else "password age unknown")
                                       + (" · never expires" if self.prop(u, "pwdneverexpires") else "")})
            self.add("spn", "medium", "User accounts registered as services (SPN)", rows,
                     "A service running under a normal user account has a password a human chose, "
                     "and any domain member can request a Kerberos ticket for it. That ticket can be "
                     "attacked offline, so the password strength is the only protection.",
                     "Move these services to group Managed Service Accounts (gMSA): Windows then uses a "
                     "random 240-character password and rotates it. Where gMSA is not possible, set a "
                     "25+ character random password and remove SPNs that are no longer used.", nu)
        nopreauth = [u for u in users if self.prop(u, "dontreqpreauth")]
        if nopreauth:
            self.add("nopreauth", "high", "Accounts with Kerberos pre-authentication disabled", nopreauth,
                     "Pre-authentication is what stops anyone from asking the DC for material tied to "
                     "the account password without proving anything first.",
                     "Clear DONT_REQ_PREAUTH on every account. If an old application needs it, "
                     "isolate it and give the account a long random password.", nu)

        # --- privileged groups ----------------------------------------------------
        priv = self.find_groups()
        rows = []
        sizes = []
        da_total = 0
        for gid, label in sorted(priv.items(), key=lambda kv: kv[1]):
            mem = [m for m in self.group_members(gid, {"User"}) if self.enabled(m)]
            sizes.append({"group": label, "count": len(mem)})
            if label == "Domain Admins":
                da_total += len(mem)
            for m in mem:
                d = _days_since(self.prop(m, "lastlogontimestamp"))
                flags = []
                if self.prop(m, "pwdneverexpires"):
                    flags.append("password never expires")
                if not self.prop(m, "sensitive"):
                    flags.append("delegatable")
                if d is not None and d > 90:
                    flags.append(f"inactive {d}d")
                rows.append({"id": m, "name": self.name(m), "type": "User",
                             "detail": label + (" · " + ", ".join(flags) if flags else "")})
        if rows:
            self.add("privmembers", "high" if da_total > 10 else "info",
                     "Members of privileged groups", rows,
                     f"{da_total} enabled Domain Admins. Every privileged account is one more "
                     "credential that must never be exposed on a workstation.",
                     "Keep Domain Admins in the single digits. Give admins a separate account used "
                     "only on hardened hosts, and add them to Protected Users.")
        self.priv_sizes = sorted(sizes, key=lambda r: -r["count"])

        t0_users = set()
        for gid, label in priv.items():
            if label in ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"):
                t0_users |= self.group_members(gid, {"User"})
        t0_users = {u for u in t0_users if self.enabled(u)}
        delegable = [u for u in t0_users if not self.prop(u, "sensitive")
                     and _rid(u) != "502"]
        if delegable:
            self.add("delegable", "medium", "Admin accounts not marked sensitive", delegable,
                     "Without the 'sensitive and cannot be delegated' flag (or Protected Users "
                     "membership), an admin's Kerberos ticket can be reused by a service the admin "
                     "connects to.",
                     "Tick 'Account is sensitive and cannot be delegated', or add the accounts to "
                     "the Protected Users group.", len(t0_users) or None)

        krbtgt = []
        for u in self.of_type("User"):
            if _rid(u) != "502":
                continue
            d = _days_since(self.prop(u, "pwdlastset"))
            if d is not None and d > 180:
                krbtgt.append({"id": u, "name": self.name(u), "type": "User",
                               "detail": f"password set {d} days ago"})
        if krbtgt:
            self.add("krbtgt", "medium", "krbtgt password not rotated recently", krbtgt,
                     "The krbtgt key signs every Kerberos ticket in the domain. If it ever leaked, "
                     "tickets forged with it stay valid until the key is changed twice.",
                     "Reset the krbtgt password twice, waiting for full replication between the two "
                     "resets. Microsoft publishes a script for this.")

        # --- delegation -----------------------------------------------------------
        dc_ids = {c for c in comps_all if self.prop(c, "isdc")}
        for gid, label in priv.items():
            if label == "Domain Controllers":
                dc_ids |= self.group_members(gid, {"Computer"})
        uncon = [i for i in comps + users
                 if self.prop(i, "unconstraineddelegation") and i not in dc_ids]
        if uncon:
            self.add("unconstrained", "high", "Unconstrained delegation outside domain controllers",
                     [{"id": i, "name": self.name(i), "type": self.typ(i)} for i in uncon],
                     "These hosts receive and store a full Kerberos ticket for every user who "
                     "connects to them, including administrators. One compromised host then holds "
                     "credentials it was never meant to hold.",
                     "Replace with constrained or resource-based constrained delegation, which limits "
                     "the services the host can reach.")
        con = []
        for i in comps + users:
            tgts = self.prop(i, "allowedtodelegate")
            if tgts:
                con.append({"id": i, "name": self.name(i), "type": self.typ(i),
                            "detail": ", ".join(map(str, tgts[:3]))
                                      + (" · protocol transition" if self.prop(i, "trustedtoauth") else "")})
        if con:
            self.add("constrained", "info", "Constrained delegation configured", con,
                     "Legitimate when intended. Worth reviewing: each entry lets the account act as "
                     "other users towards the listed services.",
                     "Confirm every entry is still needed and that the target list is as narrow as possible.")

        # --- machines ----------------------------------------------------------------
        os_count = defaultdict(int)
        for c in comps:
            os_count[str(self.prop(c, "operatingsystem") or "unknown")] += 1
        self.os_breakdown = sorted(({"os": k, "count": v} for k, v in os_count.items()),
                                   key=lambda r: -r["count"])
        unsup = [{"id": c, "name": self.name(c), "type": "Computer",
                  "detail": str(self.prop(c, "operatingsystem"))}
                 for c in comps if UNSUPPORTED_OS.search(str(self.prop(c, "operatingsystem") or ""))]
        if unsup:
            self.add("unsupported_os", "high", "Unsupported operating systems", unsup,
                     "No security updates. Known vulnerabilities stay open permanently, and these "
                     "hosts usually also lack modern protections like SMB signing or Credential Guard.",
                     "Upgrade. Where a system cannot move, isolate it on its own network segment with "
                     "strict firewall rules and no domain admin logons.", nc)
        w10 = [{"id": c, "name": self.name(c), "type": "Computer",
                "detail": str(self.prop(c, "operatingsystem"))}
               for c in comps if WIN10.search(str(self.prop(c, "operatingsystem") or ""))]
        if w10:
            self.add("win10", "medium", "Windows 10 (mainstream support ended October 2025)", w10,
                     "Only covered if the organisation pays for Extended Security Updates.",
                     "Plan the move to Windows 11, or budget for ESU.", nc)
        has_laps_data = any(self.prop(c, "haslaps") is not None for c in comps)
        if has_laps_data:
            nolaps = [c for c in comps if not self.prop(c, "haslaps") and c not in dc_ids]
            if nolaps:
                self.add("nolaps", "high", "Computers without LAPS", nolaps,
                         "Without LAPS the local administrator password is usually identical across "
                         "machines, so one recovered password opens all of them.",
                         "Deploy Windows LAPS and let it randomise and rotate the local admin password "
                         "per machine.", nc)
        stale_c = []
        for c in comps:
            d = _days_since(self.prop(c, "lastlogontimestamp"))
            if d is not None and d > 90:
                stale_c.append({"id": c, "name": self.name(c), "type": "Computer",
                                "detail": f"last seen {d} days ago", "sort": d})
        stale_c.sort(key=lambda r: -r["sort"])
        if stale_c:
            self.add("stale_computers", "low", "Computer accounts inactive for over 90 days", stale_c,
                     "Machines that no longer exist but still have a valid account in the domain.",
                     "Disable, then delete after a retention period.", nc)

        # --- data left in attributes ---------------------------------------------------
        leaks = []
        for i in list(users) + list(comps):
            desc = self.prop(i, "description")
            if isinstance(desc, str) and SECRET_IN_TEXT.search(desc):
                leaks.append({"id": i, "name": self.name(i), "type": self.typ(i), "detail": desc})
        if leaks:
            self.add("description", "high", "Possible credentials in description fields", leaks,
                     "Every authenticated user can read the description attribute of every object.",
                     "Remove the text and rotate anything that was written there. Store secrets in a "
                     "password manager instead.")

        # --- domain -------------------------------------------------------------------
        fl = [{"id": d, "name": self.name(d), "type": "Domain",
               "detail": f"functional level {self.prop(d, 'functionallevel')}"}
              for d in self.domains
              if re.search(r"2000|2003|2008|2012", str(self.prop(d, "functionallevel") or ""))]
        if fl:
            self.add("functionallevel", "medium", "Old domain functional level", fl,
                     "Older levels miss protections such as Protected Users, Authentication Policies "
                     "and modern Kerberos defaults.",
                     "Raise the domain and forest functional level once all DCs support it.")
        if self.trusts:
            nofilter = [t for t in self.trusts if t.get("sidfiltering") is False]
            self.add("trusts", "medium" if nofilter else "info", "Domain trusts",
                     [{"name": f"{t['domain']} → {t['target']}", "type": "Trust",
                       "detail": f"direction {t.get('direction')} · type {t.get('type')} · "
                                 f"SID filtering {t.get('sidfiltering')}"} for t in self.trusts],
                     "A trust extends your security boundary to another domain: its compromise can "
                     "become yours." + (" Some trusts have SID filtering disabled." if nofilter else ""),
                     "Review whether each trust is still needed. Enable SID filtering and consider "
                     "selective authentication.")

        # --- certificate services ----------------------------------------------------
        cas = self.of_type("EnterpriseCA")
        if cas:
            san = [c for c in cas if self.prop(c, "isuserspecifiessanenabled")]
            if san:
                self.add("ca_san", "high", "CA accepts a subject supplied in the request", san,
                         "With EDITF_ATTRIBUTESUBJECTALTNAME2 set, a certificate request can name any "
                         "account as its subject, so an issued certificate can identify someone else.",
                         "Remove the flag on the CA (certutil -setreg policy\\EditFlags "
                         "-EDITF_ATTRIBUTESUBJECTALTNAME2) and restart the CA service.")
            self.add("ca_inventory", "info", "Certificate authorities",
                     [{"id": c, "name": self.name(c), "type": "EnterpriseCA"} for c in cas],
                     "Certificate services are an authentication path into the domain and deserve the "
                     "same protection as a domain controller.",
                     "Keep CAs patched, restrict who can manage them, and review published templates "
                     "regularly.")
        tmpl = self.of_type("CertTemplate")
        if tmpl:
            weak = [{"id": t, "name": self.name(t), "type": "CertTemplate",
                     "detail": "subject supplied in request"
                               + ("" if self.prop(t, "requiresmanagerapproval") else " · no manager approval")}
                    for t in tmpl if self.prop(t, "enrolleesuppliessubject")]
            if weak:
                self.add("tmpl_san", "high", "Templates where the requester chooses the subject", weak,
                         "If such a template also allows client authentication, a certificate can be "
                         "issued in someone else's name.",
                         "Build the subject from Active Directory instead, or require manager approval "
                         "on the template.", len(tmpl))

        self._analyse_more(users, comps, priv, t0_users, dc_ids)
        self._build_charts(users, comps)

        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.checks.sort(key=lambda c: (order[c["severity"]], -c["count"]))

        self.stats = {
            "domains": list(self.domains.values()),
            "collected": self.collected,
            "users": len(users_all), "users_enabled": nu,
            "computers": len(comps_all), "computers_enabled": nc,
            "groups": len(self.of_type("Group")),
            "ous": len(self.of_type("OU")),
            "gpos": len(self.of_type("GPO")),
            "dcs": len(dc_ids),
            "domain_admins": da_total,
            "objects": len(self.objects),
            "files": self.files,
        }


    # ================= extra hygiene checks =================
    def groups_of(self, oid):
        """All groups an object belongs to, directly or through nesting."""
        out, stack = set(), list(self.member_of.get(oid, ()))
        while stack:
            g = stack.pop()
            if g in out:
                continue
            out.add(g)
            stack.extend(self.member_of.get(g, ()))
        return out

    def _nesting_path(self, member, group, limit=6):
        """Shortest chain of groups from a member to a group (membership only)."""
        from collections import deque
        q, prev = deque([member]), {member: None}
        while q:
            x = q.popleft()
            if x == group:
                break
            for g in self.member_of.get(x, ()):
                if g not in prev:
                    prev[g] = x
                    q.append(g)
        if group not in prev:
            return []
        chain, cur = [], group
        while cur is not None:
            chain.append(cur)
            cur = prev[cur]
        return list(reversed(chain))[: limit + 1]

    @staticmethod
    def _dn_parent(dn):
        if not isinstance(dn, str) or "," not in dn:
            return ""
        return dn.split(",", 1)[1].upper()

    def _analyse_more(self, users, comps, priv, t0_users, dc_ids):
        nu, nc = len(users), len(comps)
        priv_any = set()
        for gid in priv:
            priv_any |= self.group_members(gid, {"User"})
        priv_enabled = {u for u in priv_any if self.enabled(u)}

        # readable password attributes
        rows = []
        for u in self.of_type("User"):
            attrs = [k for k in ("userpassword", "unixpassword", "unicodepassword", "sfupassword")
                     if self.prop(u, k) not in (None, "", [], False)]
            if attrs:
                rows.append({"id": u, "name": self.name(u), "type": "User", "detail": ", ".join(attrs)})
        if rows:
            self.add("cleartext_attrs", "high", "Passwords stored in readable attributes", rows,
                     "userPassword, unixUserPassword and similar attributes are often readable by any "
                     "authenticated user and usually hold the password in clear or in a weak format.",
                     "Clear these attributes and rotate the passwords of the accounts concerned.")

        # privileged accounts used as services
        rows = [u for u in priv_enabled if self.prop(u, "hasspn")]
        if rows:
            self.add("priv_spn", "high", "Privileged accounts used as services (SPN)", rows,
                     "A service account that is also an administrator turns any weakness in its "
                     "password into a domain-wide problem.",
                     "Run the service under a dedicated, non-privileged gMSA and remove the account from "
                     "admin groups.", len(priv_enabled) or None)

        # privileged hygiene
        rows = []
        for u in priv_enabled:
            d = _days_since(self.prop(u, "lastlogontimestamp"))
            if d is None or d > 90:
                rows.append({"id": u, "name": self.name(u), "type": "User",
                             "detail": "never logged on" if d is None else f"last logon {d} days ago"})
        if rows:
            self.add("priv_inactive", "medium", "Inactive privileged accounts", rows,
                     "Admin rights nobody uses are pure risk: the account can still be used, but nobody "
                     "would notice.", "Remove the rights or disable the account.", len(priv_enabled) or None)
        rows = []
        for u in priv_enabled:
            d = _days_since(self.prop(u, "pwdlastset"))
            if d is not None and d > 365 and _rid(u) != "502":
                rows.append({"id": u, "name": self.name(u), "type": "User", "detail": f"password set {d} days ago"})
        if rows:
            self.add("priv_oldpw", "medium", "Privileged passwords older than one year", rows,
                     "The longer an admin password lives, the more places it has been typed and stored.",
                     "Rotate admin passwords at least yearly, ideally with a PAM or vault.",
                     len(priv_enabled) or None)
        rows = [{"id": u, "name": self.name(u), "type": "User", "detail": str(self.prop(u, "email"))}
                for u in priv_enabled if self.prop(u, "email")]
        if rows:
            self.add("priv_mail", "low", "Privileged accounts with a mailbox", rows,
                     "Admin accounts that read mail are exposed to phishing with full rights.",
                     "Keep a separate, non-privileged account for mail and browsing.", len(priv_enabled) or None)
        disabled_priv = [u for u in priv_any if not self.enabled(u)]
        if disabled_priv:
            self.add("priv_disabled", "low", "Disabled accounts still in privileged groups", disabled_priv,
                     "Harmless while disabled, but one re-enable away from admin rights.",
                     "Remove them from the privileged groups.")

        # orphaned adminCount
        rows = [u for u in users if self.prop(u, "admincount") and u not in priv_any]
        if rows:
            self.add("admincount_orphan", "low", "adminCount still set on accounts that are no longer admins",
                     rows,
                     "AdminSDHolder protection stays on these accounts after they leave admin groups: "
                     "their permissions stop inheriting and drift over time.",
                     "Clear adminCount and re-enable permission inheritance on these accounts.", nu)

        # computers in privileged groups
        rows = []
        for gid, label in priv.items():
            if label in ("Domain Controllers", "Read-only Domain Controllers"):
                continue
            for m in self.group_members(gid, {"Computer"}):
                if m not in dc_ids:
                    rows.append({"id": m, "name": self.name(m), "type": "Computer", "detail": label})
        if rows:
            self.add("priv_computers", "medium", "Computer accounts in privileged groups", rows,
                     "Anyone who controls one of these machines gets the group's rights.",
                     "Remove computer accounts from admin groups; grant specific rights instead.")

        # nesting depth in privileged groups
        rows = []
        for gid, label in priv.items():
            for m in self.group_members(gid, {"User"}):
                if gid in self.member_of.get(m, ()):
                    continue
                chain = self._nesting_path(m, gid)
                if len(chain) > 3:
                    rows.append({"id": m, "name": self.name(m), "type": "User",
                                 "detail": " → ".join(self.name(x).split("@")[0] for x in chain)})
        if rows:
            self.add("priv_nesting", "low", "Admin rights granted through deep group nesting", rows,
                     "When rights come through several nested groups, nobody sees who is really an admin.",
                     "Flatten admin group membership so it can be read at a glance.")

        # operator / forest groups not empty
        rows = []
        for gid, label in priv.items():
            if label in ("Account Operators", "Server Operators", "Print Operators", "Backup Operators",
                         "Schema Admins", "Enterprise Admins"):
                mem = [m for m in self.group_members(gid, {"User", "Computer"}) if self.enabled(m)]
                for m in mem:
                    rows.append({"id": m, "name": self.name(m), "type": self.typ(m), "detail": label})
        if rows:
            self.add("operators", "medium", "Members in groups that should stay empty", rows,
                     "Operator groups carry broad, poorly understood rights on DCs; Schema and Enterprise "
                     "Admins are only needed during forest changes.",
                     "Empty these groups and add people only for the duration of a change.")

        # built-in accounts
        rows = []
        for u in self.of_type("User"):
            r = _rid(u)
            if r == "501" and self.enabled(u):
                rows.append({"id": u, "name": self.name(u), "type": "User", "detail": "Guest is enabled"})
            if r == "500":
                d = _days_since(self.prop(u, "lastlogontimestamp"))
                p = _days_since(self.prop(u, "pwdlastset"))
                bits = []
                if d is not None and d < 30:
                    bits.append(f"used {d} days ago")
                if p is not None and p > 365:
                    bits.append(f"password {p} days old")
                if bits:
                    rows.append({"id": u, "name": self.name(u), "type": "User", "detail": ", ".join(bits)})
        if rows:
            self.add("builtin", "high" if any("Guest" in r["detail"] for r in rows) else "medium",
                     "Built-in Administrator / Guest accounts", rows,
                     "The built-in accounts are known to everyone and cannot be locked out like normal ones.",
                     "Keep Guest disabled; keep the built-in Administrator unused with a long vaulted password.")

        # Pre-Windows 2000 Compatible Access
        rows = []
        for gid in self.objects:
            if _sid_tail(gid) == "S-1-5-32-554":
                for m in self.members.get(gid, ()):
                    t = _sid_tail(m)
                    if t in ("S-1-1-0", "S-1-5-11", "S-1-5-7"):
                        rows.append({"id": m, "name": {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users",
                                                       "S-1-5-7": "Anonymous Logon"}[t],
                                     "type": "Group", "detail": "member of Pre-Windows 2000 Compatible Access"})
        if rows:
            self.add("prew2k", "medium", "Broad groups in Pre-Windows 2000 Compatible Access", rows,
                     "This legacy group grants read access to many user and group attributes. With "
                     "Everyone or Anonymous inside, that read access opens up to almost anyone.",
                     "Remove Everyone, Anonymous Logon and Authenticated Users from the group once no "
                     "pre-2000 system depends on it.")

        # domain controllers
        dcs = [c for c in dc_ids if c in self.objects]
        rows = [{"id": c, "name": self.name(c), "type": "Computer", "detail": str(self.prop(c, "operatingsystem"))}
                for c in dcs if UNSUPPORTED_OS.search(str(self.prop(c, "operatingsystem") or ""))]
        if rows:
            self.add("dc_os", "high", "Domain controllers on unsupported Windows", rows,
                     "The most sensitive servers of the domain no longer receive security fixes.",
                     "Promote new DCs on a supported Windows Server and demote these.")
        if len(dcs) == 1:
            self.add("single_dc", "medium", "Only one domain controller", dcs,
                     "No redundancy: losing this server stops authentication for the whole domain, and "
                     "restoring it is harder than replicating.",
                     "Add a second domain controller, ideally on another host and site.")

        # computer accounts not renewing their password
        rows = []
        for c in comps:
            d = _days_since(self.prop(c, "pwdlastset"))
            if d is not None and d > 90:
                rows.append({"id": c, "name": self.name(c), "type": "Computer",
                             "detail": f"machine password {d} days old", "sort": d})
        rows.sort(key=lambda r: -r["sort"])
        if rows:
            self.add("comp_pwd", "low", "Computer accounts not renewing their password", rows,
                     "Windows changes machine passwords every 30 days. A much older one means the machine "
                     "is gone or the renewal is blocked.",
                     "Confirm the machine still exists; remove it, or fix the renewal (GPO 'Disable machine "
                     "account password changes').", nc)

        # SID history
        rows = []
        for i in users + comps + self.of_type("Group"):
            sh = self.prop(i, "sidhistory") or self.prop(i, "_sidhistory")
            if sh:
                rows.append({"id": i, "name": self.name(i), "type": self.typ(i),
                             "detail": ", ".join(map(str, sh[:3]))})
        if rows:
            self.add("sidhistory", "medium", "Objects carrying SID history", rows,
                     "SID history grants the rights of an old SID on top of the current ones. Useful "
                     "during a migration, risky afterwards.",
                     "Clean SID history once the migration is finished.")

        # recent creations / never changed password / logon scripts
        rows = []
        for u in users:
            d = _days_since(self.prop(u, "whencreated"))
            if d is not None and d <= 30:
                rows.append({"id": u, "name": self.name(u), "type": "User", "detail": f"created {d} days ago"})
        if rows:
            self.add("recent", "info", "Accounts created in the last 30 days", rows,
                     "Worth a quick review: every new account should match a known request.",
                     "Check each one against your joiner process.", nu)
        rows = []
        for u in users:
            c = self.prop(u, "whencreated")
            p = self.prop(u, "pwdlastset")
            dc = _days_since(c)
            try:
                same = c and p and abs(float(p) - float(c)) < DAY
            except (TypeError, ValueError):
                same = False
            if same and dc is not None and dc > 365:
                rows.append({"id": u, "name": self.name(u), "type": "User",
                             "detail": f"created {dc} days ago, password never changed"})
        if rows:
            self.add("pw_never_changed", "low", "Passwords never changed since the account was created", rows,
                     "Often the initial password set by IT, sometimes shared or predictable.",
                     "Force a change at next logon, or disable the account if unused.", nu)
        rows = [{"id": u, "name": self.name(u), "type": "User", "detail": str(self.prop(u, "logonscript"))}
                for u in users if self.prop(u, "logonscript")]
        if rows:
            self.add("logonscripts", "info", "Accounts with a logon script", rows,
                     "Inventory for review: logon scripts run at every sign-in, so who can edit the script "
                     "files matters.",
                     "Check that only admins can write to the script locations.", nu)

        # default containers
        rows = []
        for i in users + comps:
            r = _rid(i)
            if r and int(r) < 1000:
                continue
            dn = str(self.prop(i, "distinguishedname") or "").upper()
            if ",CN=USERS,DC=" in dn or ",CN=COMPUTERS,DC=" in dn:
                rows.append({"id": i, "name": self.name(i), "type": self.typ(i),
                             "detail": "CN=Users" if ",CN=USERS," in dn else "CN=Computers"})
        if rows:
            self.add("default_containers", "low", "Objects left in the default containers", rows,
                     "CN=Users and CN=Computers are not OUs: no GPO can be linked to them, so these objects "
                     "only get domain-wide policies.",
                     "Move them into OUs; redirect new objects with redirusr / redircmp.")

        # groups and GPOs
        rows = [g for g in self.of_type("Group") if not self.members.get(g) and (_rid(g) or "0").isdigit()
                and int(_rid(g) or 0) >= 1000]
        if rows:
            self.add("empty_groups", "info", "Empty groups", rows,
                     "Leftovers from old projects make access reviews longer and easier to get wrong.",
                     "Delete groups that are empty and no longer referenced.", len(self.of_type("Group")))
        gpos = self.of_type("GPO")
        has_links = any(self.links.values())
        if gpos and has_links:
            rows = [g for g in gpos if not self.links.get(g)
                    and not self.links.get(str(self.prop(g, "gpcpath") or "").upper())]
            # links are stored by GUID: match the {GUID} part of the GPO's name/path too
            def guid_of(g):
                m = re.search(r"\{([0-9A-F-]{36})\}", str(self.prop(g, "gpcpath") or g).upper())
                return m.group(1) if m else g
            linked_guids = {re.sub(r"[{}]", "", k) for k in self.links}
            rows = [g for g in gpos if g not in self.links and guid_of(g) not in linked_guids]
            if rows:
                self.add("unlinked_gpos", "low", "GPOs linked nowhere", rows,
                         "They apply to nothing, but still get read during reviews and can be linked by mistake.",
                         "Back them up and delete the ones nobody needs.", len(gpos))

        # domain policy (when the collector provides it)
        for d in self.domains:
            P = self.objects[d]["props"]
            rows = []
            mpl = P.get("minpwdlength")
            if isinstance(mpl, (int, float)) and mpl < 12:
                rows.append({"name": self.name(d), "type": "Domain", "detail": f"minimum password length {int(mpl)}"})
            lt = P.get("lockoutthreshold")
            if isinstance(lt, (int, float)) and lt == 0:
                rows.append({"name": self.name(d), "type": "Domain", "detail": "account lockout disabled"})
            ph = P.get("pwdhistorylength")
            if isinstance(ph, (int, float)) and ph < 12:
                rows.append({"name": self.name(d), "type": "Domain", "detail": f"password history {int(ph)}"})
            if rows:
                self.add("pwd_policy_" + d[-6:], "medium", f"Weak default password policy ({self.name(d)})", rows,
                         "The default domain policy applies to every account without a fine-grained policy.",
                         "Aim for 12+ characters (14+ for admins), a lockout threshold, and a history of 12+.")
            maq = P.get("machineaccountquota")
            if isinstance(maq, (int, float)) and maq > 0:
                self.add("maq_" + d[-6:], "medium", "Any user can join computers to the domain",
                         [{"name": self.name(d), "type": "Domain", "detail": f"ms-DS-MachineAccountQuota = {int(maq)}"}],
                         "Each user can create up to this many computer accounts, which are then fully "
                         "controlled by them inside the domain.",
                         "Set ms-DS-MachineAccountQuota to 0 and delegate domain join to a dedicated group.")

        # certificate templates usable for anything
        rows = []
        for t in self.of_type("CertTemplate"):
            P = self.objects[t]["props"]
            ekus = P["effectiveekus"] if "effectiveekus" in P else P.get("ekus")
            any_purpose = isinstance(ekus, list) and ("2.5.29.37.0" in ekus or len(ekus) == 0)
            if any_purpose and self.prop(t, "enabled", True) is not False:
                rows.append({"id": t, "name": self.name(t), "type": "CertTemplate",
                             "detail": "no EKU (any use)" if not ekus else "Any Purpose EKU"})
        if rows:
            self.add("tmpl_anypurpose", "medium", "Certificate templates usable for any purpose", rows,
                     "A certificate with no usage restriction is valid for things the template was never "
                     "meant for, including authentication.",
                     "Give every template the narrowest Extended Key Usage it needs.")

        # overview block
        self.overview = {
            "domains": [{"name": self.name(d),
                         "functional_level": self.prop(d, "functionallevel"),
                         "sid": d, "created": _days_since(self.prop(d, "whencreated"))}
                        for d in self.domains],
            "dcs": [{"id": c, "name": self.name(c), "os": self.prop(c, "operatingsystem"),
                     "last_logon": _days_since(self.prop(c, "lastlogontimestamp"))} for c in dcs],
            "trusts": self.trusts,
            "servers": sum(1 for c in comps if "server" in str(self.prop(c, "operatingsystem") or "").lower()),
            "workstations": sum(1 for c in comps if "server" not in str(self.prop(c, "operatingsystem") or "").lower()),
            "privileged_users": len(priv_enabled),
        }

    def _build_charts(self, users, comps):
        def buckets(ids, key, edges=(30, 90, 180, 365)):
            labels = ["< 30 d", "30-90 d", "90-180 d", "180-365 d", "> 1 year", "never"]
            out = [0] * len(labels)
            for i in ids:
                d = _days_since(self.prop(i, key))
                if d is None:
                    out[-1] += 1
                    continue
                for n, e in enumerate(edges):
                    if d < e:
                        out[n] += 1
                        break
                else:
                    out[4] += 1
            return [{"label": l, "count": c} for l, c in zip(labels, out)]
        self.charts = {
            "user_logon": buckets(users, "lastlogontimestamp"),
            "user_pwd": buckets(users, "pwdlastset"),
            "computer_logon": buckets(comps, "lastlogontimestamp"),
        }

    # ================= inventory explorer =================
    COLS = {
        "User": ["name", "enabled", "privileged", "last_logon", "pwd_age", "flags", "ou", "description"],
        "Computer": ["name", "enabled", "os", "role", "last_logon", "pwd_age", "flags", "ou"],
        "Group": ["name", "members", "users_total", "privileged", "description"],
        "OU": ["name", "objects", "gpos", "description"],
        "GPO": ["name", "linked_to", "created"],
        "CertTemplate": ["name", "flags", "ekus"],
        "EnterpriseCA": ["name", "flags"],
        "Domain": ["name", "functional_level", "created"],
    }

    def _priv_set(self):
        if not hasattr(self, "_priv_cache"):
            ps = set()
            for gid in self.find_groups():
                ps |= self.group_members(gid)
                ps.add(gid)
            self._priv_cache = ps
        return self._priv_cache

    def _ou_of(self, oid):
        dn = self.prop(oid, "distinguishedname")
        parent = self._dn_parent(dn)
        if not parent:
            return ""
        first = parent.split(",")[0]
        return first.split("=", 1)[-1].title() if "=" in first else first

    def _row(self, oid):
        n = self.objects[oid]; t = n["type"]; P = n["props"]
        priv = oid in self._priv_set()
        r = {"id": oid, "name": n["name"], "type": t}
        if t == "User":
            flags = [f for f, k in (("SPN", "hasspn"), ("no-preauth", "dontreqpreauth"),
                                    ("pwd-never-expires", "pwdneverexpires"), ("pwd-not-required", "passwordnotreqd"),
                                    ("unconstrained", "unconstraineddelegation"), ("sensitive", "sensitive"),
                                    ("adminCount", "admincount")) if P.get(k)]
            r.update(enabled=self.enabled(oid), privileged=priv,
                     last_logon=_days_since(P.get("lastlogontimestamp")), pwd_age=_days_since(P.get("pwdlastset")),
                     flags=flags, ou=self._ou_of(oid), description=P.get("description") or "")
        elif t == "Computer":
            flags = [f for f, k in (("unconstrained", "unconstraineddelegation"), ("LAPS", "haslaps"),
                                    ("constrained", "allowedtodelegate")) if P.get(k)]
            os_ = str(P.get("operatingsystem") or "")
            r.update(enabled=self.enabled(oid), os=os_,
                     role="DC" if P.get("isdc") or oid in self._dc_cache() else ("server" if "server" in os_.lower() else "workstation"),
                     last_logon=_days_since(P.get("lastlogontimestamp")), pwd_age=_days_since(P.get("pwdlastset")),
                     flags=flags, ou=self._ou_of(oid))
        elif t == "Group":
            r.update(members=len(self.members.get(oid, ())), users_total=len(self.group_members(oid, {"User"})),
                     privileged=oid in self.find_groups_cache(), description=P.get("description") or "")
        elif t == "OU":
            dn = str(P.get("distinguishedname") or "").upper()
            r.update(objects=self._ou_counts().get(dn, 0),
                     gpos=sum(1 for g, tg in self.links.items() if oid in tg),
                     description=P.get("description") or "")
        elif t == "GPO":
            tg = self.links.get(oid) or set()
            m = re.search(r"\{([0-9A-F-]{36})\}", str(P.get("gpcpath") or "").upper())
            if m:
                for k, v in self.links.items():
                    if m.group(1) in k:
                        tg = tg | v
            r.update(linked_to=sorted(self.name(x) for x in tg), created=_days_since(P.get("whencreated")))
        elif t == "CertTemplate":
            flags = [f for f, k in (("requester-supplies-subject", "enrolleesuppliessubject"),
                                    ("manager-approval", "requiresmanagerapproval"),
                                    ("client-auth", "authenticationenabled")) if P.get(k)]
            r.update(flags=flags, ekus=P["effectiveekus"] if "effectiveekus" in P else (P.get("ekus") or []))
        elif t == "EnterpriseCA":
            r.update(flags=["SAN-from-request"] if P.get("isuserspecifiessanenabled") else [])
        elif t == "Domain":
            r.update(functional_level=P.get("functionallevel"), created=_days_since(P.get("whencreated")))
        return r

    def _dc_cache(self):
        if not hasattr(self, "_dcs"):
            dcs = {c for c in self.of_type("Computer") if self.prop(c, "isdc")}
            for gid, lab in self.find_groups().items():
                if lab == "Domain Controllers":
                    dcs |= self.group_members(gid, {"Computer"})
            self._dcs = dcs
        return self._dcs

    def find_groups_cache(self):
        if not hasattr(self, "_fg"):
            self._fg = self.find_groups()
        return self._fg

    def _ou_counts(self):
        if not hasattr(self, "_ouc"):
            c = defaultdict(int)
            for i, n in self.objects.items():
                if n["type"] in ("User", "Computer", "Group"):
                    c[self._dn_parent(n["props"].get("distinguishedname"))] += 1
            self._ouc = c
        return self._ouc

    def type_counts(self):
        c = defaultdict(int)
        for n in self.objects.values():
            c[n["type"]] += 1
        return {t: c.get(t, 0) for t in self.COLS}

    def query(self, typ, q="", sort="name", desc=False, page=0, size=50, flt=""):
        if typ not in self.COLS:
            raise ValueError("unknown type")
        ids = self.of_type(typ)
        rows = [self._row(i) for i in ids]
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in " ".join(str(v) for v in r.values()).lower()]
        if flt == "enabled":
            rows = [r for r in rows if r.get("enabled")]
        elif flt == "disabled":
            rows = [r for r in rows if r.get("enabled") is False]
        elif flt == "privileged":
            rows = [r for r in rows if r.get("privileged")]
        elif flt == "stale":
            rows = [r for r in rows if r.get("last_logon") is None or (r.get("last_logon") or 0) > 90]
        elif flt == "flagged":
            rows = [r for r in rows if r.get("flags")]

        def key(r):
            v = r.get(sort)
            if isinstance(v, list):
                return (0, len(v))
            if v is None:
                return (1, 0) if not desc else (-1, 0)
            return (0, v if not isinstance(v, str) else v.lower())
        try:
            rows.sort(key=key, reverse=desc)
        except TypeError:
            rows.sort(key=lambda r: str(r.get(sort)), reverse=desc)
        total = len(rows)
        size = max(1, min(int(size), 500))
        page = max(0, int(page))
        return {"type": typ, "cols": self.COLS[typ], "total": total, "page": page, "size": size,
                "rows": rows[page * size:(page + 1) * size], "all": rows}

    def detail(self, oid):
        oid = str(oid).upper()
        n = self.objects.get(oid)
        if not n:
            return None
        P = dict(n["props"])
        for k in ("lastlogontimestamp", "lastlogon", "pwdlastset", "whencreated"):
            if k in P:
                d = _days_since(P[k])
                P[k] = "never" if d is None else f"{d} days ago"
        P = {k: v for k, v in sorted(P.items()) if v not in (None, "", [], {}) and not k.startswith("_")}
        ref = lambda i: {"id": i, "name": self.name(i), "type": self.typ(i)}
        direct = sorted(self.member_of.get(oid, ()), key=self.name)
        allg = sorted(self.groups_of(oid), key=self.name)
        out = {"id": oid, "name": n["name"], "type": n["type"], "row": self._row(oid), "props": P,
               "member_of": [ref(g) for g in direct],
               "member_of_nested": [ref(g) for g in allg if g not in direct],
               "findings": [{"id": c["id"], "title": c["title"], "severity": c["severity"]}
                            for c in self.checks if any(it.get("id") == oid for it in c["items"])]}
        if n["type"] == "Group":
            out["members"] = [ref(m) for m in sorted(self.members.get(oid, ()), key=self.name)][:1000]
            out["members_total_users"] = len(self.group_members(oid, {"User"}))
        if n["type"] == "GPO":
            out["linked_to"] = self._row(oid).get("linked_to", [])
        return out

    # ---------------- output ----------------
    def report(self):
        sev = defaultdict(int)
        for c in self.checks:
            sev[c["severity"]] += 1
        return {
            "label": self.label,
            "stats": self.stats,
            "severity": dict(sev),
            "privileged_groups": self.priv_sizes,
            "os_breakdown": self.os_breakdown,
            "charts": self.charts,
            "overview": self.overview,
            "checks": self.checks,
            "seconds": self.seconds,
        }
