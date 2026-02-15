Mərhələ 1: Protokolun Fundamental Strukturunun Öyrənilməsi
[ ] 1. LDAP-ın Tarixi: X.500 standartını və "Lightweight" (yüngül) fəlsəfəsini başa düş.

[ ] 2. Kataloq vs Database: Niyə LDAP-ın oxuma əməliyyatları üçün (R-heavy) optimallaşdırıldığını öyrən.

[ ] 3. Protocol Stack: LDAP-ın OSI modelində Layer 7 (Application) üzərindəki yerini analiz et.

[ ] 4. Default Portlar: 389 (LDAP), 636 (LDAPS), 3268 (Global Catalog) və 3269 (GC over SSL) fərqləri.

[ ] 5. ASN.1 və BER: LDAP paketlərinin kodlaşdırıldığı Abstract Syntax Notation One və Basic Encoding Rules prinsiplərini öyrən.

[ ] 6. LDIF Formatı: Məlumatın import/export edilməsi üçün istifadə olunan mətn formatı (LDAP Data Interchange Format).

[ ] 7. RootDSE: Server haqqında ilkin kəşfiyyat məlumatlarını (naming contexts, capabilities) verən kök giriş.

[ ] 8. Naming Contexts: Domainin necə bölündüyünü (Configuration, Schema, Domain Partitions) anla.

==================================================================================================================================================================

Mərhələ 2: Data Modeli və Obyekt İerarxiyası
[ ] 9. Entry (Giriş): Kataloqdakı ən kiçik obyekt vahidini anla.

[ ] 10. Attributes: cn, sn, uid, dc, ou, memberOf kimi ən çox istifadə olunan atributlar.

[ ] 11. Distinguished Name (DN): Obyektin unikal tam ünvanının sintaksisi.

[ ] 12. Relative Distinguished Name (RDN): DN içindəki tək bir komponent.

[ ] 13. Object Classes: top, person, organizationalUnit, computer kimi siniflərin irsiyyət (inheritance) sistemi.

[ ] 14. Schema Analysis: Hansı atributun hansı obyektlə işləyə biləcəyini müəyyən edən qaydalar toplusu.

[ ] 15. DIT (Directory Information Tree): İerarxik ağac strukturunu vizuallaşdır.

[ ] 16. Operational Attributes: Normalda gizli olan (creatorsName, modifyTimestamp) atributların necə çağırılması.

==================================================================================================================================================================

Mərhələ 3: LDAP Əməliyyatları (Operations)
[ ] 17. Bind Operation (Simple): İstifadəçi adı və şifrə ilə sadə autentifikasiya.

[ ] 18. Anonymous Bind: Heç bir məlumat daxil etmədən girişin mümkünlüyü (Pentesting üçün kritikdir).

[ ] 19. SASL Bind: GSSAPI (Kerberos), DIGEST-MD5 kimi qabaqcıl autentifikasiya metodları.

[ ] 20. Search Operation: Filter, Scope və Base DN anlayışlarını dərindən öyrən.

[ ] 21. Search Scope: Base (tək obyekt), OneLevel (bir alt səviyyə) və Subtree (bütün ağac).

[ ] 22. Unbind & Abandon: Sessiyanın bağlanması və davam edən sorğunun ləğvi.

[ ] 23. Modify Operation: Mövcud atributların dəyişdirilməsi və ya silinməsi.

[ ] 24. Add/Delete: Yeni entry-lərin yaradılması və idarə olunması.

==================================================================================================================================================================

Mərhələ 4: Pentesting və Enumeration Texnikaları
[ ] 25. Null Session Testing: Şifrəsiz məlumat çəkmə imkanlarını yoxla.

[ ] 26. User Enumeration: Bütün istifadəçi siyahısını və onların detallarını çəkmək.

[ ] 27. Group Membership: Kritik qrupların (Admins, Backup Operators) üzvlərini analiz etmək.

[ ] 28. LDAP Injection: Axtarış filtrlərinə *, (, & kimi simvollarla müdaxilə.

[ ] 29. UAC (User Account Control) Decoding: İstifadəçi statusunu (bağlı, şifrəsi vaxtı keçmiş və s.) bitmask ilə oxumaq.

[ ] 30. Password Policy Discovery: Şifrə uzunluğu, mürəkkəblik və lockout limitlərini öyrənmək.

[ ] 31. Service Principal Names (SPN): Kerberoasting hücumları üçün hədəf siyahısı toplamaq.

[ ] 32. Sensitive Data in Attributes: description, comment, info kimi sahələrdə unudulmuş şifrələri axtarmaq.

[ ] 33. Domain Trust Discovery: Digər domainlərlə olan etibarlılıq əlaqələrini üzə çıxarmaq.

[ ] 34. GPO Enumeration: Group Policy-lərin LDAP üzərindən necə göründüyünü anla.

==================================================================================================================================================================

Mərhələ 5: Qabaqcıl Funksionallıq və Təhlükəsizlik
[ ] 35. LDAP Paged Results: 1000 entry limitini aşmaq üçün 1.2.840.113556.1.4.319 kontrolunu öyrən.

[ ] 36. Server Side Sorting: Nəticələrin server tərəfində sıralanması.

[ ] 37. Referrals: Sorğunun avtomatik başqa bir Domain Controller-ə yönləndirilməsi (Handling referrals).

[ ] 38. StartTLS: Port 389 üzərində təhlükəsiz kanalın (TLS) açılması prosesi.

[ ] 39. Replication Metadata: Obyektin hansı DC-də yaradıldığını və nə vaxt dəyişdiyini görmək.

[ ] 40. Capability Discovery: Serverin hansı LDAP versiyalarını və extension-ları dəstəklədiyini yoxla.

==================================================================================================================================================================

Mərhələ 6: Tool Development (Kodlaşdırma)
[ ] 41. Socket Setup: Seçdiyin dildə (Python, Go və ya C#) TCP/UDP socket əlaqəsi.

[ ] 42. LDAP Library Selection: ldap3 (Python) və ya goldap (Go) kimi kitabxanaların seçilməsi və ya sıfırdan yazılması.

[ ] 43. Filter Builder: Dinamik axtarış filtrləri yaradan modul yazmaq.

[ ] 44. Error Handling: LDAP Error 49 (invalid creds), Error 53 (unwilling to perform) və s. idarəetməsi.

[ ] 45. Multi-threading: Eyni anda bir neçə naming context üzrə axtarış sürətləndirmə.

[ ] 46. Export Modulu: Nəticələri JSON, CSV və Greppable formatda çıxarmaq.

[ ] 47. Interactive Shell: Tool daxilində canlı LDAP gəzintisi (Browsing) funksiyası.

[ ] 48. BloodHound Compatibility: Toplanan məlumatların BloodHound JSON formatına çevrilməsi.

[ ] 49. Fuzzing & Testing: Tool-u Active Directory, OpenLDAP və 389 Directory Server üzərində sınaqdan keçir.

[ ] 50. Optimization: Paged results və asinxron sorğularla performansı artır.





