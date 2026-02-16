# FTP Enumeration and Exploitation Technique

---

# 1. Nmap

## Identify Current Domain Context

```bash
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-ftps -sV -sC <target_ip>
nmap -p 2121 --script ftp-vsftpd-backdoor,ftp-bounce,ftp-syst,ftp-* -sV 10.129.8.214
nmap -p 21 --script ftp-brute --script-args userdb=/usr/share/wordlists/rockyou.txt,passdb=/usr/share/wordlists/rockyou.txt,ftp-brute.timeout=5s -sV <target_ip>
nmap -sS -sV -sC -p- --script banner,ftp-* -oN ftp_deep.txt <target_ip>
```

# 2. Medusa

## Brute force

```bash






