# IP Reputation Scanner

SOC, SIEM ve güvenlik operasyon ekipleri için geliştirilmiş
modüler bir IP reputation analiz aracıdır.

Bu proje, IP reputation verilerinin nasıl toplandığını,
birleştirildiğini (correlation) ve operasyonel süreçlerde
nasıl kullanılabileceğini göstermeyi amaçlar.

---

## Proje Kapsamı (Project Scope)

Bu repository, **community edition** bir IP reputation engine sunar.

Enterprise-grade SIEM / SOAR entegrasyonları, otomatik whitelist işlemleri
ve vendor-specific (ürüne özel) akışlar bu repository dışında,
ticari kullanım kapsamında sağlanmaktadır.

---

## Özellikler (Features)

- AbuseIPDB reputation score analizi
- IPQualityScore üzerinden fraud, proxy, TOR ve bot tespiti
- IP owner / ASN bilgisi alma
- Renkli ve okunabilir CLI çıktısı
- Excel raporlama (Blacklist / Whitelist sayfaları)
- Multi-threaded (çoklu iş parçacığı) analiz
- SIEM / SOAR entegrasyonu için **sanitize edilmiş örnek akış**

---

## Case 1 — Standalone IP Reputation Scanner (Community Edition - Included)

SOC analistleri, blue team ve security researcher’lar için
manuel IP incelemelerinde kullanılabilecek bir CLI aracıdır.

### Kullanım Senaryoları

- Manuel IP investigation
- Incident Response süreçlerinde enrichment
- SOC alert triage
- Threat hunting öncesi hazırlık

### Kurulum (Installation)

```bash
python -m pip install -r requirements.txt
```
### Kullanım (Usage)

```bash
python iprep-cli.py ip.txt
```
## Case 2 — SIEM / SOAR Entegrasyonu (Sanitize Edilmiş Örnek)

Bu case, kavramsal bir entegrasyon örneği olarak sunulmuştur.
Çalışan bir enterprise entegrasyonu içermez.
