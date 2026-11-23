import sys; sys.argv=["x"]; import os; sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import server as S
ok=fail=0
def c(name, cond, info=""):
    global ok,fail
    if cond: ok+=1; print(f"PASS {name}")
    else: fail+=1; print(f"FAIL {name}  {info}")
a=S.build_argv({"target":"10.0.0.1"})
c("target only", a==["/bin/bash", str(S.LINWINPWN),"-t","10.0.0.1","-o",str(S.DEFAULT_OUTPUT)], a)
a=S.build_argv({"offline":True,"target":"10.0.0.1","password":"p"})
c("offline before -t", a.index("--offline") < a.index("-t"), a)
try: S.build_argv({}); c("no target rejected", False)
except ValueError: c("no target rejected", True)
a=S.build_argv({"offline":True})
c("offline without target ok", "--offline" in a, a)
a=S.build_argv({"target":"t","domain":"d","user":"u","password":"pw","dc_domain":"dd",
  "ldap_port":"636","dns_ip":"1.2.3.4","interface":"tun0","attacker_ip":"5.6.7.8",
  "targets":"DC","user_wordlist":"/u.txt","pass_wordlist":"/p.txt"})
for flag,val in [("-d","d"),("-u","u"),("-p","pw"),("--dc-domain","dd"),("--ldap-port","636"),
  ("--dns-ip","1.2.3.4"),("-I","tun0"),("-a","5.6.7.8"),("-T","DC"),("-U","/u.txt"),("-P","/p.txt")]:
    c(f"flag {flag}", flag in a and a[a.index(flag)+1]==val, a)
for k,flag in [("hash","-H"),("aeskey","-A"),("kerb","-K"),("cert","-C")]:
    a=S.build_argv({"target":"t",k:"X"})
    c(f"auth {k} -> {flag}", flag in a and a[a.index(flag)+1]=="X", a)
a=S.build_argv({"target":"t","cert":"c.pfx","certpass":"secret"})
c("cert-pass", "--cert-pass" in a and a[a.index("--cert-pass")+1]=="secret", a)
bmap={"ldaps":"--ldaps","ldap_sign":"--ldap-sign","ldap_bind":"--ldap-bind","force_kerb":"--force-kerb",
  "dns_tcp":"--dns-tcp","use_ip":"--use-ip","no_exec":"--no-exec","verbose":"--verbose","auto_config":"--auto-config"}
a=S.build_argv(dict({"target":"t"}, **{k:True for k in bmap}))
for k,flag in bmap.items(): c(f"bool {flag}", flag in a, a)
a=S.build_argv({"target":"t","ldaps":False})
c("false flag omitted", "--ldaps" not in a, a)
a=S.build_argv({"target":"t","auto":True})
c("auto flag", a[-1]=="--auto", a)
a=S.build_argv({"target":"t","output":"/tmp/out"})
c("custom output", a[a.index("-o")+1]=="/tmp/out", a)
a=S.build_argv({"target":"t","user":"guest","password":""})
c("user + empty password -> -p ''", "-p" in a and a[a.index("-p")+1]=="", a)
a=S.build_argv({"target":"t","user":"guest"})
c("no password key -> no -p", "-p" not in a, a)
a=S.build_argv({"target":"t","user":"","password":""})
c("null session -> no -p", "-p" not in a, a)
a=S.build_argv({"target":"t","user":"u","password":"","hash":"aad3:31d6"})
c("hash auth with empty password -> no -p", "-p" not in a and "-H" in a, a)
print(f"\n{ok}/{ok+fail} passed")
sys.exit(1 if fail else 0)
