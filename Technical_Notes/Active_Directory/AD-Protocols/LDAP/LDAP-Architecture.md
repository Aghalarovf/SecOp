# LDAP Pentesting Learning Roadmap

---

## Mərhələ 1: Protokolun Fundamental Strukturunun Öyrənilməsi

- [ ] 1. LDAP-ın Tarixi  
      X.500 standartını və "Lightweight" fəlsəfəsini başa düş.

- [ ] 2. Kataloq vs Database  
      Niyə LDAP-ın oxuma əməliyyatları üçün (R-heavy) optimallaşdırıldığını öyrən.

- [ ] 3. Protocol Stack  
      LDAP-ın OSI modelində Layer 7 (Application) üzərindəki yerini analiz et.

- [ ] 4. Default Portlar  
      389 (LDAP), 636 (LDAPS), 3268 (Global Catalog) və 3269 (GC over SSL) fərqləri.

- [ ] 5. ASN.1 və BER  
      LDAP paketlərinin kodlaşdırıldığı prinsipləri öyrən.

- [ ] 6. LDIF Formatı  
      Məlumatın import/export edilməsi üçün istifadə olunan mətn formatı.

- [ ] 7. RootDSE  
      Server haqqında ilkin kəşfiyyat məlumatlarını öyrən.

- [ ] 8. Naming Contexts  
      Domain bölünməsini (Configuration, Schema, Domain Partitions) anla.

---

## Mərhələ 2: Data Modeli və Obyekt İerarxiyası

- [ ] 9. Entry (Giriş)  
      Kataloqdakı ən kiçik obyekt vahidini anla.

- [ ] 10. Attributes  
      cn, sn, uid, dc, ou, memberOf kimi atributlar.

- [ ] 11. Distinguished Name (DN)  
      Obyektin unikal tam ünvanının sintaksisi.

- [ ] 12. Relative Distinguished Name (RDN)  
      DN içindəki tək komponent.

- [ ] 13. Object Classes  
      top, person, organizationalUnit, computer sinifləri və irsiyyət sistemi.

- [ ] 14. Schema Analysis  
      Atribut və obyekt qaydalarını müəyyən edən struktur.

- [ ] 15. DIT (Directory Information Tree)  
      İerarxik ağac strukturunu vizuallaşdır.

- [ ] 16. Operational Attributes  
      Gizli atributların çağırılması.

---

## Mərhələ 3: LDAP Əməliyyatları (Operations)

- [ ] 17. Bind Operation (Simple)  
      İstifadəçi adı və şifrə ilə autentifikasiya.

- [ ] 18. Anonymous Bind  
      Şifrəsiz girişin mümkünlüyü.

- [ ] 19. SASL Bind  
      GSSAPI, DIGEST-MD5 kimi metodlar.

- [ ] 20. Search Operation  
      Filter, Scope və Base DN anlayışları.

- [ ] 21. Search Scope  
      Base, OneLevel və Subtree fərqləri.

- [ ] 22. Unbind & Abandon  
      Sessiyanın bağlanması və sorğunun ləğvi.

- [ ] 23. Modify Operation  
      Mövcud atributların dəyişdirilməsi.

- [ ] 24. Add/Delete  
      Entry yaradılması və silinməsi.

---

## Mərhələ 4: Pentesting və Enumeration Texnikaları

- [ ] 25. Null Session Testing  
      Şifrəsiz məlumat çəkmə imkanlarını yoxla.

- [ ] 26. User Enumeration  
      İstifadəçi siyahısını toplamaq.

- [ ] 27. Group Membership  
      Kritik qrupların üzvlərini analiz etmək.

- [ ] 28. LDAP Injection  
      Axtarış filtrlərinə müdaxilə texnikaları.

- [ ] 29. UAC Decoding  
      İstifadəçi statusunu bitmask ilə oxumaq.

- [ ] 30. Password Policy Discovery  
      Şifrə siyasətlərini analiz etmək.

- [ ] 31. Service Principal Names (SPN)  
      Kerberoasting üçün hədəflər toplamaq.

- [ ] 32. Sensitive Data in Attributes  
      description, comment və info sahələrini yoxlamaq.

- [ ] 33. Domain Trust Discovery  
      Domainlər arası etibarlılığı analiz etmək.

- [ ] 34. GPO Enumeration  
      Group Policy-lərin LDAP üzərindən görünməsi.

---

## Mərhələ 5: Qabaqcıl Funksionallıq və Təhlükəsizlik

- [ ] 35. LDAP Paged Results  
      1000 entry limitini aşmaq.

- [ ] 36. Server Side Sorting  
      Server tərəfində sıralama.

- [ ] 37. Referrals  
      Sorğunun başqa serverə yönləndirilməsi.

- [ ] 38. StartTLS  
      Port 389 üzərində TLS açılması.

- [ ] 39. Replication Metadata  
      Obyekt dəyişiklik tarixçəsi.

- [ ] 40. Capability Discovery  
      Serverin dəstəklədiyi LDAP versiyaları və extension-lar.

---

## Mərhələ 6: Tool Development (Kodlaşdırma)

- [ ] 41. Socket Setup  
      TCP socket əlaqəsi qurmaq.

- [ ] 42. LDAP Library Selection  
      ldap3, goldap və ya sıfırdan implementasiya.

- [ ] 43. Filter Builder  
      Dinamik filter yaradan modul.

- [ ] 44. Error Handling  
      LDAP error kodlarının idarə olunması.

- [ ] 45. Multi-threading  
      Paralel axtarışların sürətləndirilməsi.

- [ ] 46. Export Modulu  
      JSON, CSV və Greppable çıxış.

- [ ] 47. Interactive Shell  
      Canlı LDAP browsing funksiyası.

- [ ] 48. BloodHound Compatibility  
      Məlumatların uyğun formata çevrilməsi.

- [ ] 49. Fuzzing & Testing  
      Fərqli LDAP serverlərində test.

- [ ] 50. Optimization  
      Asinxron sorğular və performans artırılması.

---







