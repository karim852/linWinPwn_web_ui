"""Tests for creds_parser: builds synthetic linWinPwn output files (fake test
hashes only) and checks each format is parsed, deduped and matched to cracks.

    python3 web_ui/tests/test_creds_parser.py
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from creds_parser import CredVault, NTLM, CLEARTEXT, KERB_KEY, KERBEROAST, ASREP  # noqa: E402

ok = fail = 0


def check(name, cond, info=""):
    global ok, fail
    if cond:
        ok += 1; print(f"PASS  {name}" + (f"  ({info})" if info else ""))
    else:
        fail += 1; print(f"FAIL  {name}" + (f"  ({info})" if info else ""))


def build(root):
    d = os.path.join(root, "linWinPwn_corp.local")
    cred = os.path.join(d, "Credentials"); kerb = os.path.join(d, "Kerberos")
    os.makedirs(cred); os.makedirs(kerb)
    w = lambda p, t: open(p, "w").write(t)
    w(os.path.join(cred, "ntds_dump_corp.local.txt"), """\
corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
corp.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
corp.local\\jsmith:1104:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
corp.local\\svc_sql:1120:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
corp.local\\Administrator:aes256-cts-hmac-sha1-96:3f6c9b1a2d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddee00
corp.local\\legacy_svc:CLEARTEXT:Summer2023!
""")
    # same NTDS dumped a second time (dedup)
    w(os.path.join(cred, "secretsdump_corp.local_2.txt"),
      "corp.local\\jsmith:1104:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::\n")
    w(os.path.join(cred, "laps_dump_corp.local.txt"),
      "LAPS  10.0.0.21  445  WS01  Computer: WS01$     Password: Xk9#mLp2!qRt\n")
    w(os.path.join(kerb, "kerberoast_hashes_corp.local.txt"),
      "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$abcd$ef01\n"
      "$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web01*$1122$3344\n")
    w(os.path.join(kerb, "asreproast_hashes_corp.local.txt"),
      "$krb5asrep$23$legacy_app@CORP.LOCAL:aabb$ccdd\n")
    # john cracked svc_sql's kerberoast and jsmith's NT hash
    w(os.path.join(kerb, "kerberoast_john_results_corp.local.txt"),
      "SpringBreak1!     (svc_sql)\n1 password hash cracked, 1 left\n")
    w(os.path.join(cred, "johnNTLM_output_1.txt"),
      "Hunter2024!     (jsmith)\n")
    return d


def rec(v, rtype, user):
    for r in v.records.values():
        if r["type"] == rtype and r["username"].lower() == user.lower():
            return r
    return None


def main():
    tmp = tempfile.mkdtemp()
    build(tmp)
    v = CredVault(tmp).scan()
    r = v.report(reveal=True)
    st = r["stats"]

    check("finds nested Credentials/Kerberos folders", st["files"] == 7, f"{st['files']} files")
    check("NTLM hashes parsed", st["by_type"].get(NTLM) == 4, st["by_type"])
    check("dedup identical NT hash across two files",
          len([x for x in v.records.values() if x["type"] == NTLM and x["username"] == "jsmith"]) == 1)
    check("jsmith NT hash lists both source files",
          len(rec(v, NTLM, "jsmith")["sources"]) == 2)
    check("kerberos key parsed", st["by_type"].get(KERB_KEY) == 1)
    check("cleartext from secretsdump", rec(v, CLEARTEXT, "legacy_svc")["value"] == "Summer2023!")
    check("LAPS password parsed (trailing $ stripped)", rec(v, CLEARTEXT, "WS01") is not None)
    check("kerberoast parsed", st["by_type"].get(KERBEROAST) == 2)
    check("asrep parsed", st["by_type"].get(ASREP) == 1)

    check("cleartext counts as cracked", rec(v, CLEARTEXT, "legacy_svc")["cracked"] == "Summer2023!")
    check("empty NT hash flagged cracked", rec(v, NTLM, "krbtgt")["cracked"] == "(empty password)")
    check("john match by username (kerberoast)", rec(v, KERBEROAST, "svc_sql")["cracked"] == "SpringBreak1!")
    check("john match by username (NT hash)", rec(v, NTLM, "jsmith")["cracked"] == "Hunter2024!")
    check("crack of an account propagates to its NT hash too",
          rec(v, NTLM, "svc_sql")["cracked"] == "SpringBreak1!")
    check("a truly uncracked account stays uncracked", rec(v, NTLM, "svc_web") is None
          and rec(v, KERBEROAST, "svc_web")["cracked"] is None)
    check("total cracked count", st["cracked"] == 6, st["cracked"])

    # masking
    m = v.report(reveal=False)
    admin = [x for x in m["records"] if x["username"] == "Administrator" and x["type"] == NTLM][0]
    check("NTLM masked by default", "…" in admin["value"] and admin["value"] != "8846f7eaee8fb117ad06bdd830b7586c")
    ct = [x for x in m["records"] if x["username"] == "legacy_svc"][0]
    check("cleartext masked as dots", set(ct["value"]) == {"•"} and ct["cracked"] == "••••••")
    kr = [x for x in m["records"] if x["type"] == KERBEROAST][0]
    check("roast hash masked with length", "chars)" in kr["value"])
    check("reveal exposes the value", v.record(admin["key"], reveal=True)["value"] == "8846f7eaee8fb117ad06bdd830b7586c")

    # overlay persistence
    k = rec(v, NTLM, "svc_sql")["key"]
    v.records[k]["notes"] = "lateral to SQL01"
    v.records[k]["cracked"] = "Sql2023!"
    man = v._add(NTLM, "extra", "deadbeefdeadbeefdeadbeefdeadbeef", "manual entry", domain="corp.local")
    man["manual"] = True
    v.save_overlay()
    v2 = CredVault(tmp).scan(); v2.load_overlay()
    check("notes persist across rescan", rec(v2, NTLM, "svc_sql")["notes"] == "lateral to SQL01")
    check("manual crack persists", rec(v2, NTLM, "svc_sql")["cracked"] == "Sql2023!")
    check("manual entry persists and is flagged", rec(v2, NTLM, "extra") and rec(v2, NTLM, "extra")["manual"])

    # CSV formula-safety value
    man2 = v._add(NTLM, "evil", "=cmd", "manual entry")
    pub = v._public(man2, reveal=True)
    check("dangerous value carried as-is to _public (server prefixes on CSV write)", pub["value"] == "=cmd")

    # empty / missing
    check("empty folder yields nothing", CredVault(tempfile.mkdtemp()).scan().report()["stats"]["total"] == 0)
    check("missing folder does not crash", CredVault("/tmp/nope-nope").scan().report()["stats"]["total"] == 0)

    print(f"\n{ok}/{ok + fail} passed")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
