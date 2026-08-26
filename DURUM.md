# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Canlı bir URL'in CORS (Cross-Origin Resource Sharing) yanlış yapılandırmasını denetleyen CLI aracı — gerçek bug bounty raporlarının büyük bölümünün arkasındaki zafiyet sınıfı: reflected-origin + credentials politikası, herhangi bir web sitesinin bir kurbanın oturumu üzerinden authenticated bir cross-origin istek yapıp yanıtı okumasına izin veriyor.
- 4 farklı Origin header gönderiliyor: keyfi bir origin (herhangi bir origin yansıtılıyor mu), `null` origin (sandboxed iframe/data: URI'den erişilebilir), naive `endswith()` kontrolünü kandıran bir "suffix bypass" (`evil<target>` — nokta sınırı yok), naive substring/prefix kontrolünü kandıran bir "subdomain bypass" (gerçek host'u saldırgan kontrolündeki bir domain'in subdomain'i yapıyor).
- `Access-Control-Allow-Origin: *` + credentials yok kombinasyonu bilinçli olarak bulgu ÜRETMİYOR — bu, standart ve güvenli bir public API deseni (bkz. `api.github.com` örneği).
- Dosya: `cors_misconfiguration_scanner.py`, `tests/test_cors_misconfiguration_scanner.py` (20 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Test stratejisi: `scan_url()` bir `fetch` override kabul ediyor, tüm karar mantığı sentetik header kombinasyonlarına karşı ağsız test edildi (gerçek bir pozitif tetiklemek gerçek bir zafiyetli hedef gerektirirdi).
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`, bağlantı hatalarında exit code 2.
- Durum: ✅ 20/20 test gerçekten çalıştırılıp geçti, `ruff check .` temiz. CLI bu ortamda gerçek internet erişimiyle `https://api.github.com`'a karşı GERÇEKTEN çalıştırıldı: her 4 test origin'i için de `Access-Control-Allow-Origin: *` (credentials yok) döndü — doğru/güvenli desen, 0 bulgu. `sample_report.md` bu gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `CORS-Misconfiguration-Scanner` adıyla repo aç, git init + push.
