<img width="2480" height="1424" alt="image" src="https://github.com/user-attachments/assets/eccbf60f-57e1-44df-82e3-64c1ab4165fe" />

1) Winlogon.exe -
 Ctrl+Alt+Del dinləyir.
 Doğrulama prosesini LSASS-ə ötürür.

2) LogonUI -
 Ekranda gördüyün login pəncərəsi.
 Bu hissə yalnız məlumat toplayır, yoxlama etmir.

3) Winlogon --> LSASS -
 lsass.exe (Local Security Authority Subsystem Service).
 Authentication paketlərini işlədir.
 NTLM / Kerberos seçimlərini edir.
 Local və ya Domain login olduğunu müəyyən edir.

4) Authentication Package 

A) Local / Non-Domain Joined (ev kompüteri) --> 
NTLM işə düşür ( msv1_0.dll ) --> 
Parol → hash → müqayisə --> 
Local user hash-ləri SAM-da saxlanır --> 
SAM özü registry içində qorunur.

Offline hash dump, pass-the-hash buradan çıxır.

B) Domain / Remote Login (şirkət mühiti)
Kerberos + NTLM
Əsas: Kerberos
Fallback: NTLM
Netlogon - Domain Controller ilə danışır, Secure channel yaradır
Active Directory - ntds.dit içində user məlumatları var

Kerberoasting, Golden Ticket, DC Sync buradan çıxır.


**#LSASS ( Local Security Authority Subsystem Service )#**

a) LSASS RAM da işləyir. BitLocker qoruya bilmir. 
b) SYSTEM / Debug Privilege səlahiyyəti ilə Dump etmək olar. Normal User Dump mümkünsüzdür.

Saxlanır:
NTLM Hashes
Kerberos Tickets TGT/TGS
Service Tickets
Session Keys
Security Tokens
Credential Material

Hücumlar:
Pass-the-Ticket
Overpass-the-Hash
Golden / Silver Ticket









