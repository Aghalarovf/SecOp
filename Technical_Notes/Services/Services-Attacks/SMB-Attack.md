# SMB Enumeration and Exploitation Technique

---

# 1. Nmap

## Identify Current Domain Context

```bash
# Basic SMB discovery (ports + services)
nmap -p445 --open -sV -sC $IP

# Full SMB scripting (detailed enum)
nmap -p445 --script=smb* -sV -sC $IP

# Aggressive SMB enum (null sessions + shares)
nmap -p445 --script smb-enum-shares,smb-enum-users,smb-security-mode,smb-os-discovery,smb2-security-mode $IP

# Targeted share enum + vuln check
nmap -p445 --script smb-vuln*,smb-enum* $IP

# Multiple targets + output
nmap -iL targets.txt -p445 --script smb* -oA smb_enum
```

# 2. Smbclient

```bash
smbclient -L //10.10.10.10 -N
smbclient -L //10.10.10.10 -U username
smbclient -L //10.10.10.10 -U username%password
smbclient -L //10.10.10.10 -U domain\\username%password
smbclient -L //10.10.10.10 -W domain -U username
smbclient //10.10.10.10/share -U username
smbclient //10.10.10.10/share -N

# Commands

