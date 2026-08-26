# CORS Misconfiguration Scanner

![CI](https://github.com/KaanTuran28/CORS-Misconfiguration-Scanner/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

> ⚠️ **Authorized use only.** This sends real HTTP requests (with a crafted `Origin` header) to the URL you name. Only point it at a target you own or are explicitly authorized to test.

Scans a live URL for CORS (Cross-Origin Resource Sharing) misconfigurations — the same vulnerability class behind a large share of real bug-bounty reports: a reflected-origin-plus-credentials policy lets **any website** make an authenticated, cookie-bearing request to the target on a victim's behalf and read the response.

### Overview

Sends the target four crafted `Origin` headers and inspects whether `Access-Control-Allow-Origin` reflects them back (and whether `Access-Control-Allow-Credentials` is also set):

| Origin sent | What it tests |
|---|---|
| `https://evil-attacker-test.example` | Does the server reflect back *any* arbitrary origin? |
| `null` | Does the server accept the special `null` origin — reachable from a sandboxed iframe or a `data:` URI? |
| `https://evil<target-host>` (no separator) | Catches a naive `origin.endswith(target_host)` check — no dot boundary means `evilexample.com` passes a check for `example.com` |
| `https://<target-host>.evil-attacker-test.example` | Catches a naive substring/prefix check by making the *real* host a subdomain of an attacker-controlled one |

For each: reflected origin + credentials → **HIGH**; reflected origin without credentials → **MEDIUM**; `null` origin accepted → **MEDIUM**/**HIGH** depending on credentials; `Access-Control-Allow-Origin: *` combined with credentials (a combination browsers actually reject, but a real misconfiguration smell) → **MEDIUM**. A plain `*` with no credentials — the standard, safe public-API pattern — is correctly **not** flagged.

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd CORS-Misconfiguration-Scanner
pip install -e .
```

This installs a `cors-misconfiguration-scanner` command. You can also run the script directly with `python cors_misconfiguration_scanner.py` without installing.

### Usage

```bash
cors-misconfiguration-scanner --url https://api.example.com/data --output report.md
cors-misconfiguration-scanner --url https://api.example.com/data --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--url` | *(required)* | Target URL |
| `--timeout` | `5.0` | Request timeout in seconds |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

A request failure (unreachable host, DNS failure) exits `2` regardless of `--fail-on`.

### CI Integration

Run this against your own API before and after a CORS policy change:

```bash
cors-misconfiguration-scanner --url https://api.example.com/data --fail-on high
```

```yaml
# GitHub Actions step
- name: Check CORS policy for reflected-origin misconfiguration
  run: cors-misconfiguration-scanner --url https://api.example.com/data --fail-on high
```

### Example Output

See [`sample_report.md`](./sample_report.md) — real output from a live scan of `https://api.github.com` at the time this was generated: it consistently returns `Access-Control-Allow-Origin: *` with no `Access-Control-Allow-Credentials`, the correct, safe pattern for a public API — **0 findings**. The test suite (`tests/`) covers every finding type (reflected origin, `null` origin, both bypass shapes, wildcard+credentials) against mocked responses, since triggering a real positive would require an actual vulnerable target.

### Limitations

Only tests `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials` on a simple `GET`; it doesn't send a CORS preflight (`OPTIONS`) or check `Access-Control-Allow-Methods`/`Access-Control-Allow-Headers`, and it only tries four origin shapes rather than a large permutation set. A "no findings" result means these specific checks didn't fire — not a certification that the CORS policy is fully correct.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

`scan_url()` accepts a `fetch` override, so the full decision logic is tested against synthetic header combinations with no network access required.

### Project Structure

```
CORS-Misconfiguration-Scanner/
├── cors_misconfiguration_scanner.py
├── pyproject.toml
├── sample_report.md
├── tests/
│   └── test_cors_misconfiguration_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

> ⚠️ **Sadece yetkili kullanım.** Bu araç, belirttiğiniz URL'ye özel hazırlanmış bir `Origin` header'ı içeren gerçek HTTP istekleri gönderir. Sadece sahibi olduğunuz veya test etmek için açıkça yetkilendirildiğiniz bir hedefe karşı kullanın.

Canlı bir URL'yi CORS (Cross-Origin Resource Sharing) yanlış yapılandırmalarına karşı tarar — gerçek bug-bounty raporlarının büyük bir bölümünün arkasındaki aynı zafiyet sınıfı: origin'i yansıtan ve kimlik bilgilerine (credentials) izin veren bir politika, **herhangi bir web sitesinin** kurbanın adına hedefe kimlik doğrulamalı, çerez taşıyan bir istek göndermesine ve yanıtı okumasına izin verir.

### Genel Bakış

Hedefe özel hazırlanmış dört farklı `Origin` header'ı gönderir ve `Access-Control-Allow-Origin` yanıtının bunları geri yansıtıp yansıtmadığını (ve `Access-Control-Allow-Credentials` header'ının da ayarlanıp ayarlanmadığını) inceler:

| Gönderilen Origin | Neyi test eder |
|---|---|
| `https://evil-attacker-test.example` | Sunucu *herhangi bir* keyfi origin'i geri yansıtıyor mu? |
| `null` | Sunucu, sandbox'lanmış bir iframe'den veya bir `data:` URI'sinden erişilebilen özel `null` origin'ini kabul ediyor mu? |
| `https://evil<hedef-host>` (ayraç yok) | Naif bir `origin.endswith(target_host)` kontrolünü yakalar — nokta sınırı olmadığında `evilexample.com`, `example.com` için yapılan bir kontrolü geçer |
| `https://<hedef-host>.evil-attacker-test.example` | *Gerçek* host'u saldırganın kontrolündeki bir domain'in alt alan adı haline getirerek naif bir substring/prefix kontrolünü yakalar |

Her biri için: origin yansıtılıyor + credentials açık → **HIGH**; origin yansıtılıyor ama credentials kapalı → **MEDIUM**; `null` origin kabul ediliyor → credentials durumuna göre **MEDIUM**/**HIGH**; `Access-Control-Allow-Origin: *` ile credentials'ın birlikte kullanılması (tarayıcıların aslında reddettiği ama gerçek bir yanlış yapılandırma kokusu taşıyan bir kombinasyon) → **MEDIUM**. Credentials olmadan düz bir `*` — standart, güvenli public-API deseni — doğru şekilde işaretlen**mez**.

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd CORS-Misconfiguration-Scanner
pip install -e .
```

Bu, bir `cors-misconfiguration-scanner` komutu kurar. Kurulum yapmadan doğrudan `python cors_misconfiguration_scanner.py` ile de çalıştırabilirsiniz.

### Kullanım

```bash
cors-misconfiguration-scanner --url https://api.example.com/data --output report.md
cors-misconfiguration-scanner --url https://api.example.com/data --format json --output report.json
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--url` | *(zorunlu)* | Hedef URL |
| `--timeout` | `5.0` | İstek zaman aşımı (saniye) |
| `--output` | `sample_report.md` | Raporun yazılacağı dosya yolu |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem seviyesinde veya üzerinde bir bulgu varsa çıkış kodu `1` |

Bir istek hatası (erişilemeyen host, DNS hatası) `--fail-on` ayarından bağımsız olarak `2` ile çıkış yapar.

### CI Entegrasyonu

Bunu bir CORS politikası değişikliğinden önce ve sonra kendi API'nize karşı çalıştırın:

```bash
cors-misconfiguration-scanner --url https://api.example.com/data --fail-on high
```

```yaml
# GitHub Actions adımı
- name: Check CORS policy for reflected-origin misconfiguration
  run: cors-misconfiguration-scanner --url https://api.example.com/data --fail-on high
```

### Örnek Çıktı

Bkz. [`sample_report.md`](./sample_report.md) — bu belge üretildiği sırada `https://api.github.com` adresine yapılan canlı bir taramadan alınan gerçek çıktı: sürekli olarak `Access-Control-Allow-Credentials` olmadan `Access-Control-Allow-Origin: *` döndürüyor, bu da public bir API için doğru ve güvenli desen — **0 bulgu**. Test paketi (`tests/`), gerçek bir pozitif tetiklemek gerçekten zafiyetli bir hedef gerektireceğinden, mock'lanmış yanıtlara karşı her bulgu türünü (yansıtılan origin, `null` origin, her iki bypass şekli, wildcard+credentials) kapsıyor.

### Sınırlamalar

Sadece basit bir `GET` üzerinde `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials`'ı test eder; bir CORS preflight (`OPTIONS`) göndermez veya `Access-Control-Allow-Methods`/`Access-Control-Allow-Headers`'ı kontrol etmez ve büyük bir permütasyon kümesi yerine sadece dört origin şeklini dener. "Bulgu yok" sonucu, bu spesifik kontrollerin tetiklenmediği anlamına gelir — CORS politikasının tamamen doğru olduğunun bir sertifikası değildir.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

`scan_url()` bir `fetch` override'ı kabul eder, bu sayede tüm karar mantığı ağ erişimi gerektirmeden sentetik header kombinasyonlarına karşı test edilir.

### Proje Yapısı

```
CORS-Misconfiguration-Scanner/
├── cors_misconfiguration_scanner.py
├── pyproject.toml
├── sample_report.md
├── tests/
│   └── test_cors_misconfiguration_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).
