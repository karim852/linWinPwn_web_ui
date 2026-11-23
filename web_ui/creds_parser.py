"""
Credential vault for the linWinPwn Web Console.

Scans the engagement output folder and collects, into one list, the secrets
that linWinPwn already wrote to disk during an authorised assessment: NTLM
hashes, Kerberos keys, cleartext passwords, and roastable hashes. It also
matches them against the tool's own john/hashcat result files to mark which
ones are cracked.

Scope: this module only READS files the tool produced. It parses no live
target, dumps nothing, and cracks nothing. It is a reporting and tracking
layer, like the BloodHound inventory tab. Values are returned so the vault
can show and export them; the UI masks them by default.

Manual additions, notes and "cracked" marks are kept in _creds_vault.json in
the output folder, so they survive a rescan.

Pure standard library.
"""
import json
import re
import time
from pathlib import Path

# ---- record types ----
NTLM = "ntlm"
KERB_KEY = "kerberos-key"
CLEARTEXT = "cleartext"
KERBEROAST = "kerberoast"
ASREP = "asrep"

EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"     # NT hash of an empty password

# secretsdump / NTDS line:  DOMAIN\user:RID:LM:NT:::   or   user:RID:LM:NT:::
RE_SECRETSDUMP = re.compile(
    r"^(?:(?P<domain>[^\\/:]+)[\\/])?(?P<user>[^:]+):(?P<rid>\d+):"
    r"(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::")
# kerberos key line:  DOMAIN\user:aes256-cts-hmac-sha1-96:<hex>
RE_KERBKEY = re.compile(
    r"^(?:(?P<domain>[^\\/:]+)[\\/])?(?P<user>[^:]+):"
    r"(?P<etype>aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|des-cbc-md5):"
    r"(?P<key>[0-9a-fA-F]{16,80})\s*$")
# cleartext from secretsdump:  DOMAIN\user:CLEARTEXT:password   (or :CLEAR:)
RE_CLEARTEXT = re.compile(
    r"^(?:(?P<domain>[^\\/:]+)[\\/])?(?P<user>[^:]+):(?:CLEARTEXT|CLEAR):(?P<pw>.+?)\s*$")
# LAPS line:  Computer: WS01$   Password: <pw>
RE_LAPS = re.compile(r"Computer:\s*(?P<user>[^\s]+)\s+Password:\s*(?P<pw>.+?)\s*$")
# "NTLM: lm:nt" or "NTLM: nt" following an Account: name
RE_ACCOUNT = re.compile(r"Account:\s*(?P<user>[^\s]+)")
RE_NTLM_INLINE = re.compile(r"NTLM:\s*(?:[0-9a-fA-F]{16,32}:)?(?P<nt>[0-9a-fA-F]{32})")
# roastable hashes
RE_KERBEROAST = re.compile(r"^\$krb5tgs\$\d+\$\*(?P<user>[^*$]+)\$(?P<realm>[^*$]+)\$")
RE_ASREP = re.compile(r"^\$krb5asrep\$\d+\$(?P<user>[^@:$]+)@?(?P<realm>[^:$]*)")
# john "password     (user)"  and  hashcat "hash:password"
RE_JOHN = re.compile(r"^(?P<pw>.+?)\s+\((?P<who>[^)]+)\)\s*$")

CRED_DIRS = ("Credentials", "Kerberos", "BruteForce")
# files that contain cracking results, parsed separately
CRACK_HINT = ("john_results", "john_output", "johnntlm", "cracked", "hashcat", "potfile")


def _looks_binary(path):
    return path.suffix.lower() in (".ccache", ".kirbi", ".pfx", ".pem", ".bak",
                                   ".json", ".zip", ".cache")


class CredVault:
    def __init__(self, output_dir):
        self.root = Path(output_dir)
        self.records = {}        # key -> record
        self.cracked = {}        # username(lower) -> password  and  hashvalue -> password
        self.scanned_files = 0
        self.errors = []

    # ------------- keys -------------
    @staticmethod
    def _key(rtype, domain, user, value):
        return "|".join((rtype, (domain or "").lower(), (user or "").lower(), (value or "")[:64].lower()))

    def _add(self, rtype, user, value, source, domain="", rid="", extra=None):
        user = (user or "").strip().rstrip("$")
        value = (value or "").strip()
        if not value or not user:
            return
        k = self._key(rtype, domain, user, value)
        rec = self.records.get(k)
        if rec:
            rec["sources"].add(source)
            return rec
        rec = {"key": k, "type": rtype, "domain": domain or "", "username": user,
               "rid": rid or "", "value": value, "sources": {source},
               "cracked": None, "notes": "", "manual": False,
               "first_seen": int(time.time()), "extra": extra or {}}
        self.records[k] = rec
        return rec

    # ------------- scanning -------------
    def scan(self):
        if not self.root.exists():
            return self
        # linWinPwn writes under <output>/linWinPwn_<domain>/{Credentials,Kerberos,...}
        # so look for those folders anywhere under the output root.
        files = []
        seen = set()
        for d in self.root.rglob("*"):
            if d.is_dir() and d.name in CRED_DIRS and d not in seen:
                seen.add(d)
                files += [p for p in d.rglob("*") if p.is_file() and not _looks_binary(p)]
        # cracking result files first, so matches are ready
        files.sort(key=lambda p: 0 if any(h in p.name.lower() for h in CRACK_HINT) else 1)
        for p in files:
            try:
                if any(h in p.name.lower() for h in CRACK_HINT):
                    self._parse_cracked(p)
                else:
                    self._parse_creds(p)
                self.scanned_files += 1
            except Exception as e:
                self.errors.append(f"{p.name}: {e}")
        self._apply_cracked()
        return self

    def _rel(self, p):
        try:
            return str(p.relative_to(self.root))
        except ValueError:
            return p.name

    def _parse_cracked(self, path):
        for line in path.read_text(errors="replace").splitlines():
            line = line.rstrip()
            if not line or "password hash" in line.lower() or line.startswith("Using default"):
                continue
            m = RE_JOHN.match(line)
            if m:
                who = m.group("who").strip()
                self.cracked[who.lower()] = m.group("pw")
                continue
            if ":" in line:                        # hashcat hash:password
                h, _, pw = line.partition(":")
                if re.fullmatch(r"[0-9a-fA-F]{32}", h) and pw:
                    self.cracked[h.lower()] = pw

    def _parse_creds(self, path):
        rel = self._rel(path)
        pending_acct = None
        for raw in path.read_text(errors="replace").splitlines():
            line = raw.rstrip()
            if not line:
                continue

            m = RE_SECRETSDUMP.match(line)
            if m:
                self._add(NTLM, m.group("user"), m.group("nt"), rel,
                          domain=m.group("domain") or "", rid=m.group("rid"),
                          extra={"lm": m.group("lm")})
                continue
            m = RE_KERBKEY.match(line)
            if m:
                self._add(KERB_KEY, m.group("user"), m.group("key"), rel,
                          domain=m.group("domain") or "", extra={"etype": m.group("etype")})
                continue
            m = RE_CLEARTEXT.match(line)
            if m and m.group("user").lower() not in ("cleartext", "clear"):
                self._add(CLEARTEXT, m.group("user"), m.group("pw"), rel,
                          domain=m.group("domain") or "")
                continue
            m = RE_LAPS.search(line)
            if m:
                self._add(CLEARTEXT, m.group("user"), m.group("pw"), rel, extra={"laps": True})
                continue
            m = RE_KERBEROAST.match(line)
            if m:
                self._add(KERBEROAST, m.group("user"), line, rel,
                          domain=m.group("realm"), extra={"full": line})
                continue
            m = RE_ASREP.match(line)
            if m:
                self._add(ASREP, m.group("user"), line, rel,
                          domain=m.group("realm"), extra={"full": line})
                continue
            am = RE_ACCOUNT.search(line)
            if am:
                pending_acct = am.group("user")
            nm = RE_NTLM_INLINE.search(line)
            if nm:
                user = pending_acct or re.sub(r"[\\/].*$", "", line.split()[0]) if line.split() else None
                if user:
                    self._add(NTLM, user, nm.group("nt"), rel)
                pending_acct = None

    def _apply_cracked(self):
        for rec in self.records.values():
            if rec["type"] == CLEARTEXT:
                rec["cracked"] = rec["value"]
                continue
            pw = self.cracked.get(rec["username"].lower()) or self.cracked.get(rec["value"].lower())
            if pw:
                rec["cracked"] = pw
            elif rec["type"] == NTLM and rec["value"].lower() == EMPTY_NT:
                rec["cracked"] = "(empty password)"

    # ------------- overlay (manual / notes / cracked marks) -------------
    def vault_path(self):
        return self.root / "_creds_vault.json"

    def load_overlay(self):
        p = self.vault_path()
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text())
        except Exception:
            return
        for item in data.get("manual", []):
            rec = self._add(item.get("type", NTLM), item.get("username", ""),
                            item.get("value", ""), "manual entry",
                            domain=item.get("domain", ""), rid=item.get("rid", ""))
            if rec:
                rec["manual"] = True
        for k, ov in (data.get("overlay") or {}).items():
            rec = self.records.get(k)
            if rec:
                if ov.get("notes"):
                    rec["notes"] = ov["notes"]
                if ov.get("cracked"):
                    rec["cracked"] = ov["cracked"]

    def save_overlay(self):
        manual = [{"type": r["type"], "domain": r["domain"], "username": r["username"],
                   "rid": r["rid"], "value": r["value"]}
                  for r in self.records.values() if r["manual"]]
        overlay = {}
        for r in self.records.values():
            o = {}
            if r["notes"]:
                o["notes"] = r["notes"]
            if r["cracked"] and r["type"] != CLEARTEXT:
                o["cracked"] = r["cracked"]
            if o:
                overlay[r["key"]] = o
        self.root.mkdir(parents=True, exist_ok=True)
        p = self.vault_path()
        # the vault can hold passwords typed by hand: owner-only from the first write
        import os
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps({"manual": manual, "overlay": overlay}, indent=1))
        os.chmod(str(p), 0o600)

    # ------------- output -------------
    def _public(self, r, reveal=False):
        val = r["value"]
        shown = val if reveal else self._mask(r)
        crk = r["cracked"]
        crk_shown = crk if (reveal or not crk) else "••••••"
        return {"key": r["key"], "type": r["type"], "domain": r["domain"], "username": r["username"],
                "rid": r["rid"], "value": shown, "value_len": len(val),
                "cracked": crk_shown, "is_cracked": bool(crk), "notes": r["notes"],
                "manual": r["manual"], "sources": sorted(r["sources"]),
                "extra": {k: v for k, v in r["extra"].items() if k != "full"}}

    @staticmethod
    def _mask(r):
        v = r["value"]
        if r["type"] in (KERBEROAST, ASREP):
            return v[:18] + "…" + f" ({len(v)} chars)"
        if r["type"] == CLEARTEXT:
            return "•" * min(len(v), 10)
        return v[:4] + "…" + v[-4:] if len(v) > 8 else "••••"

    def report(self, reveal=False):
        recs = sorted(self.records.values(),
                      key=lambda r: (not r["is_cracked"] if False else 0,
                                     {NTLM: 0, CLEARTEXT: 1, KERB_KEY: 2, KERBEROAST: 3, ASREP: 4}.get(r["type"], 9),
                                     r["domain"].lower(), r["username"].lower()))
        by_type, cracked = {}, 0
        domains = set()
        for r in recs:
            by_type[r["type"]] = by_type.get(r["type"], 0) + 1
            if r["cracked"]:
                cracked += 1
            if r["domain"]:
                domains.add(r["domain"])
        return {"records": [self._public(r, reveal) for r in recs],
                "stats": {"total": len(recs), "cracked": cracked, "by_type": by_type,
                          "domains": sorted(domains), "files": self.scanned_files,
                          "users": len({r["username"].lower() for r in recs})},
                "errors": self.errors}

    def record(self, key, reveal=True):
        r = self.records.get(key)
        return self._public(r, reveal) if r else None
