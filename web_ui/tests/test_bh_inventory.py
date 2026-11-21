"""Self-contained tests for bh_inventory: builds a synthetic BloodHound
collection, runs the inventory, and asserts each hygiene check fires on the
objects it should.

    python3 web_ui/tests/test_bh_inventory.py
"""
import json
import os
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from bh_inventory import Inventory          # noqa: E402

DOM = "TEST.LOCAL"
SID = "S-1-5-21-10-20-30"
NOW = int(time.time())
DAY = 86400
ok, failed = 0, 0


def check(name, cond, info=""):
    global ok, failed
    if cond:
        ok += 1
        print(f"PASS  {name}" + (f"  ({info})" if info else ""))
    else:
        failed += 1
        print(f"FAIL  {name}" + (f"  ({info})" if info else ""))


def ts(days):
    return NOW - days * DAY


def build(path):
    def user(name, rid, **p):
        props = {"name": f"{name}@{DOM}", "objectid": f"{SID}-{rid}", "domain": DOM,
                 "enabled": p.get("enabled", True),
                 "lastlogontimestamp": p.get("logon", ts(2)),
                 "pwdlastset": ts(p.get("pwdage", 30))}
        for k, v in p.items():
            if k not in ("enabled", "logon", "pwdage"):
                props[k] = v
        props.setdefault("distinguishedname", f"CN={name},OU=Staff,DC=TEST,DC=LOCAL")
        props.setdefault("whencreated", ts(800))
        return {"ObjectIdentifier": f"{SID}-{rid}", "Properties": props, "Aces": [],
                "PrimaryGroupSID": f"{SID}-513"}

    def comp(name, rid, osname, **p):
        props = {"name": f"{name}.{DOM}", "objectid": f"{SID}-{rid}", "domain": DOM,
                 "enabled": True, "operatingsystem": osname,
                 "lastlogontimestamp": p.get("logon", ts(1)), "pwdlastset": ts(10),
                 "haslaps": p.get("laps", True)}
        for k, v in p.items():
            if k not in ("logon", "laps", "pwdage"):
                props[k] = v
        props["pwdlastset"] = ts(p.get("pwdage", 10))
        props.setdefault("distinguishedname", f"CN={name},OU=Servers,DC=TEST,DC=LOCAL")
        return {"ObjectIdentifier": f"{SID}-{rid}", "Properties": props, "Aces": []}

    users = [
        user("alice", 1001),
        user("bob", 1002, logon=ts(400)),                       # stale
        user("carol", 1003, logon=0),                           # never logged on
        user("dave", 1004, pwdneverexpires=True),
        user("erin", 1005, passwordnotreqd=True),
        user("frank", 1006, pwdage=500),                        # old password
        user("svc_sql", 1007, hasspn=True, pwdage=700),
        user("legacy", 1008, dontreqpreauth=True),
        user("leaky", 1009, description="svc account password: Hunter2!"),
        user("admin1", 1010),                                   # Domain Admin, not sensitive
        user("admin2", 1011, sensitive=True),                   # Domain Admin, sensitive
        user("krbtgt", 502, pwdage=900),
        user("olduser", 1012, enabled=False),                   # disabled
        user("cleartext", 1013, userpassword="P@ss"),           # readable password attribute
        user("svc_admin", 1014, hasspn=True),                   # privileged + SPN (via nested group)
        user("former_admin", 1015, admincount=True),            # orphan adminCount
        user("oldadmin", 1016, logon=ts(200)),                  # inactive admin (Backup Operators)
        user("mailadmin", 1017, email="m@test.local", pwdage=400),  # admin with mailbox + old pwd
        user("dis_admin", 1018, enabled=False),                 # disabled but in Domain Admins
        user("newbie", 1019, whencreated=ts(5)),                # created recently
        user("initial", 1020, whencreated=ts(600), pwdage=600), # password never changed
        user("scripted", 1021, logonscript="logon.bat"),
        user("migrated", 1022, sidhistory=["S-1-5-21-9-9-9-1105"]),
        user("lost", 1023, distinguishedname="CN=lost,CN=Users,DC=TEST,DC=LOCAL"),
        user("Guest", 501),                                     # Guest enabled
        user("Administrator", 500, pwdage=500),                 # built-in admin, old password
    ]
    # whencreated == pwdlastset for "initial"
    for u in users:
        if u["Properties"]["name"].startswith("initial@"):
            u["Properties"]["pwdlastset"] = u["Properties"]["whencreated"]
    comps = [
        comp("DC01", 2001, "Windows Server 2022 Datacenter", isdc=True,
             unconstraineddelegation=True, laps=False),         # DC: must NOT be flagged
        comp("SRV1", 2002, "Windows Server 2019 Standard", unconstraineddelegation=True),
        comp("SRV2", 2003, "Windows Server 2008 R2", laps=False),   # unsupported + no LAPS
        comp("WS1", 2004, "Windows 10 Enterprise"),
        comp("WS2", 2005, "Windows 11 Enterprise", logon=ts(200)),  # stale computer
        comp("OLDPW", 2006, "Windows 11 Enterprise", pwdage=300),   # machine password not renewed
        comp("ADMPC", 2007, "Windows 11 Enterprise"),               # computer in Domain Admins
    ]
    groups = [
        {"ObjectIdentifier": f"{SID}-512",
         "Properties": {"name": f"DOMAIN ADMINS@{DOM}", "objectid": f"{SID}-512"},
         "Members": [{"ObjectIdentifier": f"{SID}-1010", "ObjectType": "User"},
                     {"ObjectIdentifier": f"{SID}-1011", "ObjectType": "User"},
                     {"ObjectIdentifier": f"{SID}-1017", "ObjectType": "User"},
                     {"ObjectIdentifier": f"{SID}-1018", "ObjectType": "User"},
                     {"ObjectIdentifier": f"{SID}-2007", "ObjectType": "Computer"},
                     {"ObjectIdentifier": f"{SID}-3001", "ObjectType": "Group"}], "Aces": []},
        # nesting: SVC-ADMINS -> TIER1 -> TIER0 -> Domain Admins
        {"ObjectIdentifier": f"{SID}-3001", "Properties": {"name": f"TIER0@{DOM}", "objectid": f"{SID}-3001"},
         "Members": [{"ObjectIdentifier": f"{SID}-3002", "ObjectType": "Group"}], "Aces": []},
        {"ObjectIdentifier": f"{SID}-3002", "Properties": {"name": f"TIER1@{DOM}", "objectid": f"{SID}-3002"},
         "Members": [{"ObjectIdentifier": f"{SID}-3003", "ObjectType": "Group"}], "Aces": []},
        {"ObjectIdentifier": f"{SID}-3003", "Properties": {"name": f"SVC-ADMINS@{DOM}", "objectid": f"{SID}-3003"},
         "Members": [{"ObjectIdentifier": f"{SID}-1014", "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": f"{SID}-3004", "Properties": {"name": f"OLD-PROJECT@{DOM}", "objectid": f"{SID}-3004"},
         "Members": [], "Aces": []},
        {"ObjectIdentifier": f"{DOM}-S-1-5-32-551",
         "Properties": {"name": f"BACKUP OPERATORS@{DOM}", "objectid": f"{DOM}-S-1-5-32-551"},
         "Members": [{"ObjectIdentifier": f"{SID}-1016", "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": f"{DOM}-S-1-5-32-554",
         "Properties": {"name": f"PRE-WINDOWS 2000 COMPATIBLE ACCESS@{DOM}", "objectid": f"{DOM}-S-1-5-32-554"},
         "Members": [{"ObjectIdentifier": f"{DOM}-S-1-5-11", "ObjectType": "Group"}], "Aces": []},
        {"ObjectIdentifier": f"{SID}-516",
         "Properties": {"name": f"DOMAIN CONTROLLERS@{DOM}", "objectid": f"{SID}-516"},
         "Members": [{"ObjectIdentifier": f"{SID}-2001", "ObjectType": "Computer"}], "Aces": []},
    ]
    domains = [{"ObjectIdentifier": SID,
                "Properties": {"name": DOM, "objectid": SID, "functionallevel": "2008 R2",
                               "minpwdlength": 7, "lockoutthreshold": 0, "pwdhistorylength": 24,
                               "machineaccountquota": 10},
                "Links": [{"GUID": "AAAAAAAA-0000-0000-0000-000000000001", "IsEnforced": False}],
                "Trusts": [{"TargetDomainName": "OTHER.LOCAL", "TrustDirection": "Inbound",
                            "TrustType": "External", "SidFilteringEnabled": False}], "Aces": []}]
    cas = [{"ObjectIdentifier": "CA1",
            "Properties": {"name": f"CA@{DOM}", "objectid": "CA1",
                           "isuserspecifiessanenabled": True}, "Aces": []}]
    gpos = [{"ObjectIdentifier": "AAAAAAAA-0000-0000-0000-000000000001",
             "Properties": {"name": f"DEFAULT POLICY@{DOM}", "objectid": "AAAAAAAA-0000-0000-0000-000000000001",
                            "gpcpath": "\\\\TEST.LOCAL\\SYSVOL\\Policies\\{AAAAAAAA-0000-0000-0000-000000000001}"}, "Aces": []},
            {"ObjectIdentifier": "BBBBBBBB-0000-0000-0000-000000000002",
             "Properties": {"name": f"ORPHAN GPO@{DOM}", "objectid": "BBBBBBBB-0000-0000-0000-000000000002",
                            "gpcpath": "\\\\TEST.LOCAL\\SYSVOL\\Policies\\{BBBBBBBB-0000-0000-0000-000000000002}"}, "Aces": []}]
    ous = [{"ObjectIdentifier": "OU-STAFF",
            "Properties": {"name": f"STAFF@{DOM}", "objectid": "OU-STAFF",
                           "distinguishedname": "OU=Staff,DC=TEST,DC=LOCAL"}, "Aces": [], "Links": []}]
    tmpl = [{"ObjectIdentifier": "T2",
             "Properties": {"name": f"ANYTHING@{DOM}", "objectid": "T2", "effectiveekus": [],
                            "enrolleesuppliessubject": False}, "Aces": []},
            {"ObjectIdentifier": "T1",
             "Properties": {"name": f"TPL@{DOM}", "objectid": "T1",
                            "enrolleesuppliessubject": True,
                            "requiresmanagerapproval": False}, "Aces": []}]

    files = {"users": users, "computers": comps, "groups": groups, "domains": domains,
             "enterprisecas": cas, "certtemplates": tmpl, "gpos": gpos, "ous": ous}
    names = []
    for t, data in files.items():
        fn = os.path.join(path, f"2026_{t}.json")
        json.dump({"meta": {"type": t, "count": len(data), "version": 5,
                            "collectionDate": "2026-11-20T10:00:00Z"}, "data": data},
                  open(fn, "w"))
        names.append(fn)
    zp = os.path.join(path, "collection.zip")
    with zipfile.ZipFile(zp, "w") as z:
        for fn in names:
            z.write(fn, os.path.basename(fn))
    return zp


def names_in(rep, cid):
    for c in rep["checks"]:
        if c["id"] == cid:
            return {i["name"].split("@")[0].split(".")[0] for i in c["items"]}
    return set()


def main():
    tmp = tempfile.mkdtemp()
    zp = build(tmp)

    rep = Inventory([zp], "test").report()
    st = rep["stats"]

    check("inventory counts", st["users"] == 26 and st["users_enabled"] == 24
          and st["computers"] == 7 and st["dcs"] == 1,
          f"{st['users_enabled']}/{st['users']} users, {st['computers']} computers, {st['dcs']} DC")
    check("domain and collection date", st["domains"] == [DOM] and st["collected"],
          st["domains"][0] if st["domains"] else "none")
    check("domain admins counted (nested, enabled)", st["domain_admins"] == 4, str(st["domain_admins"]))

    check("stale accounts", names_in(rep, "stale") == {"bob", "oldadmin"}, names_in(rep, "stale"))
    check("never logged on", names_in(rep, "never") == {"carol"}, names_in(rep, "never"))
    check("disabled accounts", names_in(rep, "disabled") == {"olduser", "dis_admin"}, names_in(rep, "disabled"))
    check("password never expires", "dave" in names_in(rep, "pwdneverexpires"))
    check("password not required", names_in(rep, "passwordnotreqd") == {"erin"})
    check("old passwords (krbtgt excluded)",
          "frank" in names_in(rep, "oldpw") and "krbtgt" not in names_in(rep, "oldpw"),
          names_in(rep, "oldpw"))
    check("SPN accounts", names_in(rep, "spn") == {"svc_sql", "svc_admin"}, names_in(rep, "spn"))
    check("no pre-auth", names_in(rep, "nopreauth") == {"legacy"})
    check("credentials in description", names_in(rep, "description") == {"leaky"})
    check("krbtgt rotation", names_in(rep, "krbtgt") == {"krbtgt"})
    check("admins not sensitive", names_in(rep, "delegable") == {"admin1", "mailadmin", "svc_admin"},
          names_in(rep, "delegable"))
    check("privileged members listed", {"admin1", "admin2", "svc_admin", "oldadmin"} <= names_in(rep, "privmembers"),
          names_in(rep, "privmembers"))

    check("unconstrained delegation skips DCs",
          names_in(rep, "unconstrained") == {"SRV1"}, names_in(rep, "unconstrained"))
    check("unsupported OS", names_in(rep, "unsupported_os") == {"SRV2"})
    check("Windows 10", names_in(rep, "win10") == {"WS1"})
    check("no LAPS skips DCs", names_in(rep, "nolaps") == {"SRV2"}, names_in(rep, "nolaps"))
    check("stale computers", names_in(rep, "stale_computers") == {"WS2"})

    print("--- extra hygiene checks ---")
    check("readable password attributes", names_in(rep, "cleartext_attrs") == {"cleartext"})
    check("privileged + SPN (through nesting)", names_in(rep, "priv_spn") == {"svc_admin"}, names_in(rep, "priv_spn"))
    check("inactive privileged", names_in(rep, "priv_inactive") == {"oldadmin"}, names_in(rep, "priv_inactive"))
    check("old privileged password", "mailadmin" in names_in(rep, "priv_oldpw"), names_in(rep, "priv_oldpw"))
    check("privileged with mailbox", names_in(rep, "priv_mail") == {"mailadmin"})
    check("disabled in privileged group", names_in(rep, "priv_disabled") == {"dis_admin"})
    check("orphan adminCount", names_in(rep, "admincount_orphan") == {"former_admin"}, names_in(rep, "admincount_orphan"))
    check("computer in privileged group", names_in(rep, "priv_computers") == {"ADMPC"})
    nest = [c for c in rep["checks"] if c["id"] == "priv_nesting"]
    check("deep nesting shows the chain",
          nest and any("SVC-ADMINS" in i["detail"] and "TIER0" in i["detail"] for i in nest[0]["items"]),
          nest[0]["items"][0]["detail"] if nest else "none")
    check("operator group members", "oldadmin" in names_in(rep, "operators"))
    b = names_in(rep, "builtin")
    check("built-in Guest enabled + Administrator old pwd", b == {"Guest", "Administrator"}, b)
    check("Guest makes it high", any(c["id"] == "builtin" and c["severity"] == "high" for c in rep["checks"]))
    check("Pre-Windows 2000 with Authenticated Users", names_in(rep, "prew2k") == {"Authenticated Users"})
    check("single DC", names_in(rep, "single_dc") == {"DC01"})
    check("machine password not renewed", names_in(rep, "comp_pwd") == {"OLDPW"}, names_in(rep, "comp_pwd"))
    check("SID history", names_in(rep, "sidhistory") == {"migrated"})
    check("created in last 30 days", names_in(rep, "recent") == {"newbie"}, names_in(rep, "recent"))
    check("password never changed", names_in(rep, "pw_never_changed") == {"initial"}, names_in(rep, "pw_never_changed"))
    check("logon scripts", names_in(rep, "logonscripts") == {"scripted"})
    check("default containers", names_in(rep, "default_containers") == {"lost"})
    check("empty groups", names_in(rep, "empty_groups") == {"OLD-PROJECT"}, names_in(rep, "empty_groups"))
    check("unlinked GPO", names_in(rep, "unlinked_gpos") == {"ORPHAN GPO"}, names_in(rep, "unlinked_gpos"))
    pp = [c for c in rep["checks"] if c["id"].startswith("pwd_policy_")]
    check("weak password policy (length + lockout, not history)",
          pp and {i["detail"] for i in pp[0]["items"]} == {"minimum password length 7", "account lockout disabled"},
          [i["detail"] for i in pp[0]["items"]] if pp else "none")
    check("machine account quota", any(c["id"].startswith("maq_") for c in rep["checks"]))
    check("any-purpose template", names_in(rep, "tmpl_anypurpose") == {"ANYTHING"})

    print("--- overview + charts ---")
    ov = rep["overview"]
    check("overview lists DCs", [d["name"] for d in ov["dcs"]] == [f"DC01.{DOM}"], ov["dcs"])
    check("overview servers/workstations", ov["servers"] == 3 and ov["workstations"] == 4, f"{ov['servers']}/{ov['workstations']}")
    lg = {b["label"]: b["count"] for b in rep["charts"]["user_logon"]}
    check("logon age buckets sum to enabled users", sum(lg.values()) == st["users_enabled"], lg)
    check("'never' bucket", lg["never"] >= 1)

    print("--- explorer ---")
    inv = Inventory([zp], "q")
    tc = inv.type_counts()
    check("type counts", tc["User"] == 26 and tc["GPO"] == 2 and tc["OU"] == 1, tc)
    q = inv.query("User", sort="pwd_age", desc=True, size=5)
    check("query paging", q["total"] == 26 and len(q["rows"]) == 5)
    ages = [r["pwd_age"] for r in q["rows"]]
    check("sort desc by password age", ages == sorted(ages, reverse=True), ages)
    check("filter privileged", {r["name"].split("@")[0] for r in inv.query("User", flt="privileged", size=100)["rows"]}
          >= {"admin1", "svc_admin"})
    check("filter disabled", {r["name"].split("@")[0] for r in inv.query("User", flt="disabled", size=100)["rows"]}
          == {"olduser", "dis_admin"})
    check("search", [r["name"] for r in inv.query("User", q="svc_sql")["rows"]] == [f"SVC_SQL@{DOM}".replace("SVC_SQL", "svc_sql")])
    cq = inv.query("Computer", size=100)["rows"]
    roles = {r["name"].split(".")[0]: r["role"] for r in cq}
    check("computer roles", roles["DC01"] == "DC" and roles["SRV1"] == "server" and roles["WS1"] == "workstation", roles)
    g = {r["name"].split("@")[0]: r for r in inv.query("Group", size=100)["rows"]}
    check("group counts (direct vs nested users)", g["DOMAIN ADMINS"]["members"] == 6
          and g["DOMAIN ADMINS"]["users_total"] == 5, (g["DOMAIN ADMINS"]["members"], g["DOMAIN ADMINS"]["users_total"]))
    gp = {r["name"].split("@")[0]: r for r in inv.query("GPO")["rows"]}
    check("GPO linked to domain", gp["DEFAULT POLICY"]["linked_to"] == [DOM] and gp["ORPHAN GPO"]["linked_to"] == [])
    ou = inv.query("OU")["rows"][0]
    check("OU object count", ou["objects"] >= 20, ou["objects"])
    d = inv.detail(f"{SID}-1014")
    check("detail: unresolved primary group named by RID",
          "Domain Users (not collected)" in [x["name"] for x in d["member_of"]], [x["name"] for x in d["member_of"]])
    check("detail: direct + nested groups", "SVC-ADMINS" in [x["name"].split("@")[0] for x in d["member_of"]]
          and {"TIER1", "TIER0", "DOMAIN ADMINS"} <= {x["name"].split("@")[0] for x in d["member_of_nested"]})
    check("detail: findings for the object", {"priv_spn", "spn"} <= {f["id"] for f in d["findings"]}, [f["id"] for f in d["findings"]])
    dg = inv.detail(f"{SID}-512")
    check("detail: group members", len(dg["members"]) == 6 and dg["members_total_users"] == 5)
    check("detail: unknown id", inv.detail("nope") is None)
    try:
        inv.query("Nope"); check("query rejects unknown type", False)
    except ValueError:
        check("query rejects unknown type", True)

    check("old functional level", len(names_in(rep, "functionallevel")) == 1)
    check("trusts flagged (no SID filtering)",
          any(c["id"] == "trusts" and c["severity"] == "medium" for c in rep["checks"]))
    check("CA SAN flag", names_in(rep, "ca_san") == {"CA"})
    check("template subject in request", names_in(rep, "tmpl_san") == {"TPL"})

    sevs = {c["severity"] for c in rep["checks"]}
    check("severities valid", sevs <= {"high", "medium", "low", "info"}, sevs)
    check("sorted by severity",
          [c["severity"] for c in rep["checks"]] ==
          sorted((c["severity"] for c in rep["checks"]),
                 key=lambda s: {"high": 0, "medium": 1, "low": 2, "info": 3}[s]))
    check("every check has why and fix",
          all(c["why"] and c["fix"] for c in rep["checks"]))

    # same data, loose folder instead of zip
    rep2 = Inventory([tmp], "folder").report()
    check("folder and zip give the same result",
          len(rep2["checks"]) == len(rep["checks"])
          and rep2["stats"]["users"] == st["users"])

    # defensive scope: no offensive tooling referenced anywhere
    blob = json.dumps(rep).lower()
    bad = [w for w in ("kerberoast", "dcsync", "attack path", "secretsdump",
                       "lsass", "impacket", "netexec", "shortest path", "exploit")
           if w in blob]
    check("no offensive tooling referenced", not bad, ", ".join(bad))

    for bad_input, label in (([tempfile.mkdtemp()], "empty folder"),):
        try:
            Inventory(bad_input, label)
            check(f"rejects {label}", False)
        except ValueError:
            check(f"rejects {label}", True)

    print(f"\n{ok}/{ok + failed} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
