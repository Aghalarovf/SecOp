Mərhələ 1: Protokolun Temelləri (1-10)
[ ] 1. SMB-nin Tarixi: IBM-in orijinal dizaynından Microsoft-un CIFS-inə keçid.

[ ] 2. SMB Dialects: SMB 1.0, 2.0, 2.1, 3.0, 3.1.1 versiyaları arasındakı fərqlər.

[ ] 3. NetBIOS vs Direct Hosting: Port 139 (NetBIOS) və Port 445 (TCP) fərqi.

[ ] 4. OSI Layer: SMB-nin Session və Application layer-dəki funksiyaları.

[ ] 5. SMB Header Structure: Paketlərin başlıq hissəsinin analizi (Command, Status, Flags).

[ ] 6. Negotiate Protocol: Client və Serverin ortaq dil (dialekt) tapması prosesi.

[ ] 7. Session Setup: Autentifikasiya paketlərinin (NTLM/Kerberos) SMB daxilində daşınması.

[ ] 8. Tree Connect: Paylaşılan qovluqlara (shares) qoşulma məntiqi.

[ ] 9. SMB2 Message Pipelining: Bir neçə sorğunun tək paketdə göndərilməsi.

[ ] 10. SMB Signing: Paket bütövlüyü və MITM hücumlarından qorunma mexanizmi.

🔐 Mərhələ 2: Autentifikasiya və Təhlükəsizlik (11-20)
[ ] 11. NTLM Handshake: Challenge-Response mexanizminin detalları.

[ ] 12. NTLM Relay: SMB-də şifrə ötürülməsi (Relaying) necə baş verir?

[ ] 13. Kerberos over SMB: Port 445 üzərindən ticket ötürülməsi.

[ ] 14. Guest Access: "Guest" hesabının aktiv olduğu mühitlərin kəşfi.

[ ] 15. Null Sessions: İstifadəçi adı və şifrə olmadan IPC$ paylaşımlarına giriş.

[ ] 16. SMB Encryption: SMB 3.0+ versiyalarında gələn şifrələmə texnologiyası.

[ ] 17. Pre-Auth Integrity: SMB 3.1.1-də MITM-in qarşısını alan yeni metod.

[ ] 18. Hash Types: LM, NTLM, Net-NTLMv1/v2 fərqləri.

[ ] 19. Pass-the-Hash: Hash vasitəsilə autentifikasiyanın SMB səviyyəsində işləməsi.

[ ] 20. Security Descriptor: Fayl və qovluq icazələrinin (ACL) idarə olunması.

🛠️ Mərhələ 3: RPC və IPC Mexanizmləri (21-35)
[ ] 21. IPC$ (Inter-Process Communication): Named Pipes anlayışı.

[ ] 22. MSRPC (Microsoft RPC): SMB üzərindən uzaqdan əmr icrası.

[ ] 23. RPC Endpoint Mapper: Port 135-in SMB ilə əlaqəsi.

[ ] 24. SAMR (SAM RPC): İstifadəçi və qrup siyahılarını çəkmək üçün protokol.

[ ] 25. LSARPC (LSA RPC): Policy və gizli məlumatların enumerasiyası.

[ ] 26. SRVSVC (Server Service): Paylaşılan qovluqların siyahısını çəkmək.

[ ] 27. NetShareEnum: ls əmrinə bənzər paylaşımları görmə funksiyası.

[ ] 28. NetUserEnum: Şəbəkə üzərindən istifadəçiləri çəkmək.

[ ] 29. NetGroupEnum: Qrupların siyahısını əldə etmək.

[ ] 30. Remote Registry: SMB vasitəsilə registry-də məlumat axtarışı.

[ ] 31. Service Control Manager (SCM): Servislərin siyahısı və idarəsi.

[ ] 32. Pipe Auditing: Hansı pipe-ların aktiv olduğunu tapmaq (\lsarpc, \samr, \netlogon).

[ ] 33. UUIDs: MSRPC interfeyslərinin unikal ID-ləri.

[ ] 34. Opnums: RPC funksiyalarının əməliyyat nömrələri.

[ ] 35. NDR (Network Data Representation): Məlumatın RPC paketləri üçün serializasiyası.

🔍 Mərhələ 4: Enumeration Texnikaları (36-50)
[ ] 36. OS Fingerprinting: SMB cavablarından OS versiyasını təxmin etmək.

[ ] 37. Hostname Resolution: NetBIOS adı və Domain adının kəşfi.

[ ] 38. Share Enumeration: Read/Write icazəsi olan qovluqların tapılması.

[ ] 39. Hidden Shares: C$, ADMIN$, IPC$ kimi gizli paylaşımların yoxlanması.

[ ] 40. File Crawling: Paylaşılan qovluqlarda rekursiv fayl axtarışı.

[ ] 41. Sensitive File Detection: .config, .txt, .ppk kimi həssas faylların tapılması.

[ ] 42. User Hunting: Şəbəkədə hansı istifadəçinin hansı maşında aktiv olduğunu tapmaq.

[ ] 43. Password Policy Enumeration: Lockout limitləri və minimum şifrə uzunluğu.

[ ] 44. Group Memberships: Hansı istifadəçinin "Backup Operators" və ya "Admins" olduğunu öyrən.

[ ] 45. System Time: Serverin vaxtını çəkməklə vaxt sinxronizasiyasını yoxlamaq.

[ ] 46. SID Enumeration: SID-lərin (Security Identifier) rekursiv sorğulanması (Lookupsids).

[ ] 47. Printer Enumeration: Paylaşılan printerlər vasitəsilə məlumat sızdırmaq.

[ ] 48. Disk Free Space: Disklərin doluluq dərəcəsini görmək.

[ ] 49. Active Sessions: Serverə hazırda bağlı olan digər istifadəçiləri görmək.

[ ] 50. Anonymous Login Check: Heç bir data vermədən nə qədər məlumat alınır?

⚡ Mərhələ 5: Pentesting və Exploitation (51-60)
[ ] 51. EternalBlue (MS17-010): SMBv1 boşluğunun texniki analizi.

[ ] 52. SMBLoris: DoS (Denial of Service) hücum mexanizmi.

[ ] 53. SMBGhost (CVE-2020-0796): SMBv3 kompressiya boşluğu.

[ ] 54. Symlink Attacks: Paylaşılan qovluqlarda simvolik link manipulyasiyası.

[ ] 55. Bruteforce/Credential Spraying: SMB üzərindən şifrə sınaqları.

[ ] 56. SMB Exec: Psexec-in işləmə prinsipi (Service creation).

[ ] 57. WMI over SMB: İdarəetmə interfeysi vasitəsilə enumeration.

[ ] 58. PrintNightmare: Spooler xidmətinin SMB vasitəsilə istismarı.

[ ] 59. PetitPotam: NTLM Relay hücumları üçün SMB-ni məcbur etmək.

[ ] 60. GPP Password Decryption: groups.xml faylında yaddan çıxan şifrələr.

💻 Mərhələ 6: Tool Development (61-70)
[ ] 61. Python Impacket: SMB və RPC modullarını dərindən öyrən.

[ ] 62. Raw Socket Connection: Port 445-ə aşağı səviyyəli qoşulma.

[ ] 63. Packet Crafting: Scapy və ya Impacket ilə xüsusi SMB paketi hazırlama.

[ ] 64. Asynchronous Scanning: Minlərlə IP-ni eyni anda daramaq (asyncio/threading).

[ ] 65. Spidering Algorithm: Paylaşımları avtomatik gəzən botun yazılması.

[ ] 66. Grep-friendly Output: Pentesterlər üçün sürətli axtarış formatı.

[ ] 67. JSON Export: BloodHound və ya digər vizuallaşdırma alətləri üçün data.

[ ] 68. Error Handling: STATUS_ACCESS_DENIED və ya STATUS_LOGON_FAILURE kodlarının analizi.

[ ] 69. Stealth Mode: IDS/IPS-ə düşməmək üçün sorğuları gecikdirmək.

[ ] 70. Integration: LDAP enumeration ilə SMB məlumatlarını birləşdirən vahid "Target Map" yaradılması.
