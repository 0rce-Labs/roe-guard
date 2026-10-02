# roe-guard — Kapsamlı Proje Spesifikasyonu & Yol Haritası

**Paket adı (çalışma adı):** roe-guard (PyPI: `roe-guard`, import: `roe_guard`)
**Marka:** 0rce Labs
**Lisans (öneri):** MIT — geniş benimseme ve entegrasyon kolaylığı için
**Durum:** v0.1 çekirdeği uygulandı (0.1.0a1, PyPI'da yayınlanmadı); politika şeması v2 ve audit kaydı v2 §14'te tanımlıdır.

---

## 1. Vizyon ve Konumlandırma

### Ne, neden

0rce'nin manifestosu "Rules of Engagement" kavramını ve "0 Unauthorized Operations — scoped, gated, logged, cleaned" ilkesini merkeze koyuyor. roe-guard, bu ilkenin genel-amaçlı, açık kaynak, herkesin kendi tooling'ine entegre edebileceği yazılım karşılığı: bir güvenlik operasyonunun (pentest, red team, otonom savunma ajanı, chaos engineering testi, hatta CI/CD'deki otomatik remediation script'i) hangi hedeflere, hangi zaman aralığında, hangi aksiyon tipleriyle dokunabileceğini programatik olarak tanımlayan ve kapsam dışına çıkan her aksiyonu engelleyen bir policy-enforcement kütüphanesi.

### Neden bu kütüphane var olmalı

Gerçek dünyada scope creep (kapsam dışına taşma) pentest/red team operasyonlarının en büyük hukuki ve operasyonel riskidir — yanlışlıkla prod veritabanı subnet'ine dokunmak, kontrat dışı bir IP'yi taramak gibi. Bugün bu kontrol çoğunlukla insan disiplinine veya ağır, enterprise SOAR platformlarına bağlı. Hafif, kod-seviyesinde, herhangi bir Python aracına (özel scanner, otonom ajan, CI script) birkaç satırla entegre edilebilen bir çözüm boşluk.

### 0rce ile ilişki

- roe-guard tamamen açık kaynak ve 0rce'nin ticari ürününden bağımsız çalışır — hiçbir 0rce müşteri verisi, algoritma veya ticari IP içermez.
- Konumlandırma: "0rce'nin sıfır-yetkisiz-operasyon ilkesinin açık kaynak referans implementasyonu." Bu hem 0rce'ye organik marka görünürlüğü sağlar hem de roe-guard'ı bağımsız, güvenilir bir güvenlik topluluğu aracı olarak konumlandırır.
- roe-guard, ileride 0rce'nin kendi platformunun açık, denetlenebilir bir bileşeni olarak kullanılabilir (opsiyonel, v0.1 kapsamında değil).

## 2. Kullanım Senaryoları

- **Pentest/Red Team Engagement:** Bir özel scanner veya exploit framework'ü, her aksiyon öncesi `roe_guard.enforce()` çağırır; kontrat dışı bir hedefe dokunma girişimi otomatik reddedilir ve loglanır.
- **Otonom Savunma/Hunt Ajanları:** #9 (hostcontain), #14 (reattack-sched) gibi gelecekteki 0rce Labs araçları, aksiyon almadan önce roe-guard ile kapsam kontrolü yapar — bu paket diğerlerinin ortak bağımlılığı olabilir.
- **CI/CD Güvenlik Otomasyonu:** Otomatik remediation script'i (örn. "şüpheli IP'yi blokla") sadece tanımlı blast-radius içinde çalışır.
- **Chaos/Security Testing:** Sentetik saldırı enjeksiyonu yapan araçlar, prod'a sızmasın diye kapsam dışı hedeflere asla dokunamaz.

## 3. Tasarım İlkeleri

1. **Fail-closed.** Policy belirsizse, parse edilemiyorsa, süresi dolmuşsa → varsayılan DENY. Asla "emin değilsen izin ver" yok.
2. **Tahrif edilemez audit log.** Her karar (ALLOW/DENY/REQUIRES_APPROVAL) hash-chain'li, append-only bir log'a yazılır — sonradan değiştirilemez.
3. **Sıfıra yakın bağımlılık.** Sadece pyyaml + stdlib. Ağır bağımlılık yok.
4. **Dürüst kapsam.** Bu bir ağ güvenlik duvarı değildir — entegre eden aracın `enforce()` çağırmasına bağlıdır. Bu sınırlama README'de ve dokümantasyonda açıkça yazılacak (bkz. §7 Tehdit Modeli).
5. **Deklaratif policy, çalıştırılabilir kod değil.** Policy dosyaları YAML `safe_load` ile okunur — hiçbir dinamik kod çalıştırma yok (RCE riskini kapatır).
6. **Kompozisyon.** Decorator, context manager ve düşük seviye fonksiyon API'si aynı anda sunulur — farklı entegrasyon tarzlarına uyar.

## 4. Mimari

```
roe_guard/
├── models.py          # Scope, Policy, Engagement, Decision, AuditEntry dataclass'ları
├── policy.py          # YAML policy dosyasını yükleme + doğrulama (schema validation)
├── engine.py          # Karar motoru: enforce(target, action_type, metadata) -> Decision
├── audit.py           # Hash-chain'li append-only audit logger
├── integrations/
│   ├── decorator.py   # @guarded(engagement) decorator
│   └── context.py     # with engagement.window(): context manager
├── cli.py              # `roe-guard validate|check|audit-verify`
└── exceptions.py       # OutOfScopeError, PolicyExpiredError, PolicyParseError
tests/
├── fixtures/
│   ├── valid_policy.yaml
│   ├── expired_policy.yaml
│   └── malformed_policy.yaml
├── test_policy.py
├── test_engine.py
├── test_audit.py
└── test_integrations.py
```

**Veri akışı:** Policy YAML → `policy.load()` → Policy nesnesi → Engagement (policy + operasyon kimliği) → her aksiyon için `engine.enforce(engagement, target, action_type)` → Decision (ALLOW/DENY/REQUIRES_APPROVAL + reason) → `audit.record(decision)` (hash-chain'e eklenir).

## 5. Policy Şeması (v0.1)

Bu bölüm şema sürümü 1'i anlatır; v2 için bkz. §14.

```yaml
engagement_id: "acme-fintech-2026-08"
valid_from: "2026-08-01T00:00:00Z"
valid_until: "2026-08-28T23:59:59Z"

scope:
  allow:
    - cidr: "10.20.0.0/16"
    - hostname: "*.staging.acme.internal"
  deny:
    - cidr: "10.20.5.0/24"        # explicit carve-out (örn. prod DB subnet)

actions:
  allow: ["recon", "exploit", "persistence-test"]
  deny: ["destructive", "data-exfil"]

blackout_windows:
  - start: "2026-08-15T00:00:00Z"
    end: "2026-08-16T00:00:00Z"
    reason: "müşteri bakım penceresi"

approval_required_for: ["persistence-test"]
approvers: ["ops-lead@acme.example"]
```

**Şema sürümü.** `schema_version` opsiyonel bir tamsayıdır; yoksa `1` kabul edilir. Bu sürümün
desteklediği en büyük değer `MAX_SCHEMA_VERSION`'dır. Daha büyük, 1'den küçük, tamsayı olmayan
(bool dahil) ya da boş bir değer `PolicyParseError` (`field` = `schema_version`) ile reddedilir.
Politika yüklenmez ve hiçbir aksiyona izin verilmez (fail-closed).

**Bilinmeyen anahtarlar.** `schema_version: 2` politikalarında tanınmayan her anahtar, her
seviyede `PolicyParseError` ile reddedilir. `x-` önekli uzantı anahtarları her sürümde yok
sayılır. v1'de `mode`, `agent`, `sandbox`, `egress` ve `approval` anahtarları
`schema_version: 2` ister. Diğer bilinmeyen v1 anahtarları `UnknownKeyWarning` ile uyarılır ve
yok sayılır. v2 blokları tanımlanana kadar v2 dosyasındaki bu bloklar da reddedilir
(fail-closed).

### Karar mantığı (öncelik sırası):

1. `valid_from`/`valid_until` dışında mı? → **DENY** (PolicyExpiredError)
2. Şu an bir `blackout_window` içinde mi? → **DENY**
3. Hedef `scope.deny`'de mi? → **DENY** (deny her zaman allow'u ezer)
4. Hedef `scope.allow`'da değil mi? → **DENY**
5. Aksiyon tipi `actions.deny`'de mi? → **DENY**
6. Aksiyon tipi `approval_required_for`'da mı? → **REQUIRES_APPROVAL**
7. Aksiyon tipi `actions.allow`'da mı? → **ALLOW**
8. Hiçbiri değilse → **DENY** (fail-closed varsayılan)

## 6. API Tasarımı (örnekler)

```python
from roe_guard import Engagement, guarded, OutOfScopeError

# Düşük seviye kullanım
engagement = Engagement.from_file("policy.yaml")
decision = engagement.check(target="10.20.3.5", action_type="exploit")
if decision.allowed:
    run_exploit(target)
else:
    log.warning(f"Blocked: {decision.reason}")

# Context manager
with engagement.window():
    for host in discovered_hosts:
        engagement.check(host, "recon").raise_if_denied()
        scan(host)


# Decorator — mevcut bir fonksiyonu saydam şekilde korur
@guarded(engagement, action_type="exploit", target_arg="host")
def run_exploit(host: str): ...
```

```bash
# CLI
roe-guard validate policy.yaml
roe-guard check --target 10.20.3.5 --action exploit --policy policy.yaml
roe-guard audit-verify audit.jsonl     # hash-chain bütünlüğünü doğrular
```

## 7. Tehdit Modeli ve Dürüst Sınırlamalar

roe-guard'ın kendisi bir güvenlik aracı olduğu için, README'de ve dokümantasyonda şu sınırlamalar açıkça belirtilecek:

1. **Bu bir ağ güvenlik duvarı değildir.** Sadece `enforce()`'u çağıran araçları kısıtlar. Entegre etmeyen bir araç bypass edebilir — bu bir SDK-seviyesi disiplin katmanıdır, ağ-seviyesi zorlama değildir.
2. **Audit log bütünlüğü** hash-chain ile tahrif tespiti sağlar, tahrifi önlemez — dosya sistemine erişimi olan biri log'u silebilir. v0.2'de opsiyonel harici anchor (örn. imzalı uzak endpoint'e periyodik hash gönderimi) düşünülebilir.
3. **Policy dosyası güvenilir bir kaynaktan gelmelidir.** YAML `safe_load` kullanıldığı için RCE riski yok, ama policy dosyasının kendisi yetkisiz değiştirilirse kapsam de facto genişleyebilir — dosya izinleri kullanıcı sorumluluğunda.
4. **Hostname hedefleri çözülmez.** CIDR deny kuralları hostname olarak verilen hedeflere uygulanmaz. IP seviyesinde kontrol zorlayan platformun işidir (§14.5).

Bu sınırlamalar bir "eksiklik" değil, tasarım gereği net kapsam — küçük, denetlenebilir, tek-iş-yapan bir kütüphane olmanın bedeli.

## 8. Kabul Kriterleri (v0.1 "bitti" tanımı)

- [x] `pip install -e .` çalışıyor
- [ ] Geçerli bir policy dosyasıyla `Engagement.from_file()` başarıyla yükleniyor
- [ ] Kapsam dışı hedef için `enforce()` → DENY, doğru reason ile
- [ ] Süresi dolmuş policy → DENY (PolicyExpiredError)
- [ ] Blackout window içinde → DENY
- [ ] `approval_required_for` eşleşmesi → REQUIRES_APPROVAL (ALLOW değil)
- [ ] Audit log hash-chain'i `roe-guard audit-verify` ile doğrulanabiliyor, kasıtlı satır değişikliği tespit ediliyor
- [ ] Decorator ve context manager her ikisi de testli
- [ ] pytest coverage ≥ %85 (bu bir güvenlik aracı, bar yüksek tutulmalı)
- [ ] README'de gerçek policy → gerçek kod → gerçek DENY/ALLOW çıktısı gösterimi
- [ ] CI: lint + test + pip-audit (bağımlılık güvenlik taraması) her PR'da

## 9. Yol Haritası

### v0.1 — Çekirdek (bu spesifikasyonun kapsamı)

Policy yükleme, karar motoru, hash-chain audit, decorator/context manager, CLI (validate, check, audit-verify).

### v0.2 — Entegrasyon Genişletmeleri

- Yaygın araçlar için hazır sarmalayıcılar (nmap subprocess wrapper — hedef kapsam dışıysa komutu hiç çalıştırmaz)
- Harici audit anchor (imzalı uzak log gönderimi)
- `approval_required_for` için basit onay akışı (CLI üzerinden `roe-guard approve <request-id>`)

### v0.3 — Ekosistem Bağlantısı

- #9 (hostcontain) ve #14 (reattack-sched) ile referans entegrasyon örnekleri
- Policy dosyaları için JSON Schema + editör otomatik-tamamlama desteği (v2 çalışmasıyla öne alındı: §14.8)

> v0.2 ve v0.3, bu dokümanın kapsamı dışında — ayrı spec'ler olarak ele alınacak.

## 10. Ticket Backlog (v0.1 — her biri tek ajan oturumuna sığacak boyutta)

| Ticket | Başlık | Çıktı |
|--------|--------|-------|
| **T1** | Repo İskeleti | pyproject.toml, paket yapısı, LICENSE (MIT), .gitignore, boş modüller, CI iskeleti. `pip install -e .` çalışıyor, `roe-guard --help` boş CLI gösteriyor. |
| **T2** | Veri Modelleri | models.py: Scope, Policy, Engagement, Decision, AuditEntry dataclass'ları + tip tanımları. Testli, tip güvenli veri modelleri. |
| **T3** | Policy Yükleme ve Doğrulama | policy.py: YAML safe_load + şema doğrulama (zorunlu alanlar, tarih formatları, CIDR geçerliliği). Bozuk/eksik policy için anlamlı hata mesajları. `load_policy(path) -> Policy`, geçerli + bozuk fixture'larla testli. |
| **T4** | Karar Motoru | engine.py: §5'teki öncelik sırasını uygulayan `enforce()` fonksiyonu. Tüm 8 karar dalı için pozitif+negatif test. `enforce(engagement, target, action_type) -> Decision`, tam kapsamlı testli. |
| **T5** | Hash-Chain Audit Logger | audit.py: Append-only JSONL, her satır bir önceki satırın hash'ini içerir. `verify()` fonksiyonu zincir bütünlüğünü kontrol eder, kasıtlı bozulmayı tespit eder. `AuditLog.record()`, `AuditLog.verify()`, testli (temiz zincir + bozuk zincir senaryosu). |
| **T6** | Decorator ve Context Manager | integrations/decorator.py + integrations/context.py: T4'ü saran ergonomik API'ler. §6'daki örnekler çalışıyor, testli. |
| **T7** | CLI | cli.py: validate, check, audit-verify komutları. T1-T6'yı birbirine bağlar. Uçtan uca çalışan CLI, entegrasyon testli. |
| **T8** | README + Gerçek Demo | Gerçek policy dosyası → gerçek CLI/API çıktısı, kurulum, kullanım, tehdit modeli (§7) özeti. Yeni kullanıcı 5 dakikada kurup çalıştırabiliyor. |
| **T9** | CI + Paketleme | GitHub Actions: pytest + ruff/black + pip-audit her PR'da. PyPI trusted publishing (tag push → otomatik yayın). Yeşil CI, `pip install roe-guard` (yayınlandığında) çalışıyor. |

**Sıra:** T1 → T2 → T3 → T4 → T5 (T4 ile paralel olabilir) → T6 → T7 → T8 → T9.

**v2 ticket backlog**

| Ticket | Başlık | Çıktı |
|--------|--------|-------|
| T13 | Public API export + `Engagement.from_file` | Kök paket 23 isimli API'yi dışa verir; `Engagement.from_file()` çalışır. |
| T14 | `schema_version` kapısı | Opsiyonel alan; desteklenmeyen sürüm `PolicyParseError` ile reddedilir (fail-closed). |
| T15 | v2 bilinmeyen anahtar reddi | v2'de bilinmeyen anahtar her seviyede reddedilir; `x-*` serbest; v1'de v2-rezerve bloklar reddedilir, diğerleri `UnknownKeyWarning`. |
| T16 | `py.typed` + mypy | PEP 561 işaretleyici; CI'da `mypy --strict` adımı. |
| T17 | Coverage eşiği | CI `fail_under` eşiğini uygular. |
| T18 | Bu SPEC | Politika şeması v2 ve audit kaydı v2 §14'te tanımlı. |
| T19 | JSON Schema v1 + v2 | Her iki sürüm için JSON Schema; editör desteği. |
| T20 | v2 yükleyici + `EnforcementMode` + `reason_code` | v2 blokları (`mode`, `agent`, `sandbox`, `egress`, `approval`) yüklenir. |
| T21 | Agent kimlik adımı | `agent.id` SPIFFE/glob eşleşmesi karar merdivenine girer. |
| T22 | `enforce_egress` | `egress` bloğu kararı karara eklenir. |
| T23 | Conformance vektörleri | Dil bağımsız politika+girdi→verdict vektörleri. |
| T24 | Audit kaydı v2 | §14.7'deki alanlar audit kaydına eklenir. |

## 11. Marka ve Yayın Notları

- **README tonu:** 0rce'nin manifestosundaki dil kaydına yakın ama daha teknik/az pazarlama — bu bir mühendislik kütüphanesi, ürün sayfası değil.
- **Katkı politikası:** CONTRIBUTING.md, dış katkıları kabul edecek şekilde net kurallarla (bu, 0rce Labs'ın ilk gerçek "topluluk yüzü" olabilir).
- **PyPI hesabı:** 0rce Labs adına ayrı bir organizasyon hesabı önerilir (kişisel hesaptan ayrı) — ileride diğer 0rce Labs paketleri (#9, #6 vb.) aynı çatı altında toplanabilir.

## 12. Açık Kararlar

- [ ] PyPI paket adı kesinleşmedi (`roe-guard` müsait mi kontrol edilmeli)
- [ ] 0rce Labs GitHub organizasyonu kurulacak mı, yoksa kişisel hesap altında mı kalacak
- [ ] v0.2'deki "harici audit anchor" için hangi mekanizma (kendi endpoint mi, üçüncü parti timestamping servisi mi)

## 13. Yönetim İş Akışı

- Bu doküman kaynak-of-truth. Her ticket bağımsız bir kodlama ajanı oturumuna verilir.
- Her ticket tamamlandığında §8'deki kabul kriterlerine ve ilgili ticket'ın "Çıktı" satırına göre gözden geçirilir.
- Mimari sapma gerekirse önce bu dokümana işlenir, sonra uygulanır.
- v0.1 tamamlandıktan sonra §9'daki v0.2 için ayrı bir spec dokümanı hazırlanır.

## 14. Politika Şeması v2 ve Audit Kaydı v2

### 14.1 Sürümleme ve anahtar kuralları

- `schema_version` alanı v1'de opsiyoneldir, yoksa `1` sayılır. v2 dosyasında zorunludur ve değeri `2`'dir.
- `MAX_SCHEMA_VERSION = 2`. Şunlar `PolicyParseError(field="schema_version")` ile reddedilir: bundan büyük değer, 1'den küçük değer, `int` olmayan değer (bool dahil) ve `null`. Sürüm kontrolü diğer bütün kontrollerden önce yapılır.
- v1 dosyasında kökte `mode`, `agent`, `sandbox`, `egress` ya da `approval` varsa: `PolicyParseError(field=<anahtar>)`, mesaj `'<anahtar>' requires schema_version: 2`.
- v1'de diğer bilinmeyen anahtarlar `UnknownKeyWarning` ile uyarılır ve yok sayılır.
- v2'de her seviyede bilinmeyen anahtar `PolicyParseError` verir; `field` alanı noktalı yoldur (ör. `egress.http.allow[1].proto`).
- `x-` ile başlayan anahtarlar her seviyede ve her sürümde yok sayılır. Kökteki `x-*` anahtarları `Policy.extensions` sözlüğüne konur. Üreticiye özgü alanlar yalnız `x-<üretici>` altında yaşar; roe-guard bunların içeriğini yorumlamaz.
- Hata `field` kuralları: bilinmeyen anahtarda anahtarın yolu, eksik zorunlu anahtarda eksik anahtarın yolu (ör. `approval.timeout_seconds`), tip ya da değer hatasında değerin yolu (ör. `egress.http.allow[0].ports[0]`). v1'in mevcut `field` değerleri değişmez; ör. kökteki eksik alanlar için `<top>`.

### 14.2 v2 alanları

Örnek — bütün v2 blokları:

```yaml
schema_version: 2
engagement_id: example-engagement-2026-10
valid_from: "2026-10-01T00:00:00Z"
valid_until: "2026-10-31T23:59:59Z"
mode: observe
scope:
  allow:
    - cidr: 192.0.2.0/24
  deny:
    - cidr: 203.0.113.0/24
actions:
  allow: [tool.read]
  deny: [tool.write]
blackout_windows:
  - start: "2026-10-10T00:00:00Z"
    end: "2026-10-11T00:00:00Z"
    reason: maintenance
approval_required_for: [tool.deploy]
approval:
  timeout_seconds: 300
  on_timeout: deny
agent:
  id: spiffe://example.org/tenant/main/agent/*/sandbox/*
  runtime: [claude-code, hermes]
sandbox:
  filesystem:
    read: [/workspace/**]
    write: [/workspace/out/**]
    deny: [/workspace/secrets/**]
egress:
  default: deny
  http:
    allow:
      - host: api.example.com
        ports: [443]
approval_required_for: [tool.deploy]
x-vendor:
  internal_note: example only
approvers: [ops-lead@exbin.example]
```

| Alan | Tip | Zorunlu | Varsayılan | Kural |
|---|---|---|---|---|
| `schema_version` | int | v2'de evet | 1 | `2` |
| `engagement_id`, `valid_from`, `valid_until`, `scope`, `actions`, `blackout_windows`, `approval_required_for`, `approvers` | v1 ile aynı | v1 ile aynı | v1 ile aynı | v1 ile aynı; bu alanlarda `null` liste v1'deki gibi `[]` sayılır |
| `mode` | str | hayır | `enforce` | `enforce` ya da `observe` |
| `agent.id` | str | blok varsa evet | — | `spiffe://` ile başlar; glob (`fnmatch.fnmatchcase`, büyük/küçük harf duyarlı) |
| `agent.runtime` | [str] | hayır | `[]` | boş olmayan dizeler |
| `sandbox.filesystem.read` / `.write` / `.deny` | [str] | hayır | `[]` | boş olmayan glob dizeleri |
| `egress.default` | str | hayır | `deny` | `deny`; v2'de başka değer tanımlı değildir |
| `egress.http.allow[].host` | str | blok varsa evet | — | boş olmayan alan adı; glob içermez |
| `egress.http.allow[].ports` | [int] | hayır | `[443, 80]` | 1–65535 aralığında; tekrarsız |
| `egress.http.allow[].proto` | str | hayır | `https` | `http` ya da `https` |
| `egress.dns.resolvers` | [str] | hayır | `[]` | boşsa platformun resolver'ı kullanılır |
| `approval.timeout_seconds` | int | blok varsa evet | — | 1–3600 aralığında |
| `approval.on_timeout` | str | hayır | `deny` | `deny`; v2'de başka değer tanımlı değildir |
| `x-*` | herhangi | hayır | — | her seviyede yok sayılır; köktekiler `Policy.extensions`'e konur |

Bilinmeyen bir değer ya da tip, ilgili yol ile `PolicyParseError` üretir (§14.1).

### 14.3 Modlar

| Durum | `enforce` | `observe` |
|---|---|---|
| `ALLOW` | İşlem geçer; olay kaydedilir | İşlem geçer; olay kaydedilir |
| `DENY` | İşlem engellenir; attempt-level sinyal üretilir | İşlem geçer; `verdict=DENY`, `mode=observe` olayı kaydedilir; sinyal AGS'ye girer |
| `REQUIRES_APPROVAL` | Onay gelene ya da zaman aşımına kadar bekletilir; zaman aşımında `DENY`; `approval` bloğu yoksa bekletilmeden engellenir | Bekletilmez, geçer; "bekletilirdi" olayı ve sinyal kaydedilir |
| Sert taban ihlali | Reddedilir; olay kaydedilir | Reddedilir; olay kaydedilir (moddan bağımsız) |
| Audit kaydı | Açık | Açık |

`mode` alanı bulunmayan bir v2 politikası `enforce` modundadır. Onboarding şablonları açıkça
`mode: observe` ile başlar; observe'dan enforce'a geçmek bir politika değişikliğidir ve audit
kaydına girer.

### 14.4 Karar merdiveni v2

v1'deki 8 adımlı sıranın başına **adım 0** eklenir; diğer adımlar ve öncelik sırası değişmez:

0. **`enforce_egress` (A-6).** İstek bir HTTP(S) çıkışı ise ve `egress` bloğu tanımlıysa:
   hedef host + port + protokol `egress.http.allow` listesinde yoksa **DENY**
   (`reason = "egress not allowed"`). Agent kimliği `agent.id` glob'larından birine
   uymuyorsa **DENY** (`reason = "agent identity not in policy"`). Kontrol tüm modlarda
   yapılır; `observe` modunda engelleme yerine "olurdu DENY" kaydı düşer.

Sonrasında v1 merdiveni aynen uygulanır (zaman penceresi → blackout → scope → actions →
approval → audit). Aynı istekte birden fazla kural ihlal edilse bile yalnız ilk ihlalin
`reason`'u döner.

### 14.5 enforce_egress

`egress` bloğu, zorlayan platformun ağ katmanına politika verisi sağlar:

- **HTTP(S) allowlist:** `egress.http.allow` girdileri host + port + protokol üçlüsüdür.
  Platform, bu listeye uymayan CONNECT/SNI hedeflerini reddeder ve olay kaydeder.
- **DNS resolver:** `egress.dns.resolvers` boş değilse platform DNS'i yalnız bu
  çözücülere yönlendirir; boşsa platformun kendi resolver'ı kullanılır.
- **Varsayılan:** `egress.default` yalnız `deny` olabilir. İzin verilmeyen her hedef
  reddedilir; hiçbir durumda allowlist genişletilmez.
- **Hostname hedefleri:** CIDR kuralları hostname hedeflerine uygulanmaz (§7); host
  allowlist'i ad bazlı çalışır.
- Bu blok bir **karar girdisidir**; ağ zorlamasının kendisi zorlayan platformun
  (ör. sandbox altyapısının) sorumluluğundadır.

### 14.6 Yeni alanlar ve uyumluluk kuralları

- v2'de yeni bir blok ya da alan eklemek `MAX_SCHEMA_VERSION`'ı artırmayı gerektirmez;
  alan v2'nin parçası olarak tanımlanır ve yükleyiciye eklenir.
- v1 dosyalarına v2 blokları eklenemez (§14.1); bir v1 dosyasının v2'ye geçmesi
  `schema_version: 2` satırının eklenmesiyle olur ve bilinmeyen anahtar kuralları o andan
  itibaren uygulanır.
- `null` liste değeri v1'deki gibi `[]` sayılır; v2'de `null` skaler değeri
  `PolicyParseError`'dır.
- `x-*` anahtarlarının içeriği hiçbir sürümde doğrulanmaz; üretici sorumluluğundadır.
- Conformance vektörleri (§14.8) her iki sürümü de kapsar; bir sürümde davranış
  değişirse vektör güncellenir ve changelog'a yazılır.

### 14.7 Audit kaydı v2

v1 audit kaydının alanları korunur; şu alanlar **eklenir**:

| Alan | Tip | Anlam |
|---|---|---|
| `schema_version` | int | Kayıt biçimi sürümü; v2 kayıtlarda `2`. |
| `mode` | str | Karar anındaki mod (`enforce` / `observe`). |
| `policy_id` | str | Karara giren politikanın `engagement_id`'si. |
| `policy_sha256` | str | Ham politika baytlarının küçük harf hex SHA-256'sı. |
| `action` | str | Verdict sonrası uygulanan aksiyon: `pass`, `block`, `hold`. |
| `reason_code` | str | Makine-okunur kısa kod; serbest metin taşımaz. |

Kurallar:

- Zincir biçimi değişmez: her kayıt bir öncekinin `entry_hash`'ini taşır; `verify()`
  tüm kayıtlar için çalışır.
- `mode=observe` kayıtlarında `verdict=DENY` + `action=pass` birlikte görülebilir; bu
  bir tutarsızlık değil, gözlem modunun tanımıdır.
- Eski okuyucular yeni alanları yok sayabilir; yeni okuyucular eksik alanları
  `schema_version: 1` kayıt olarak yorumlar.

### 14.8 JSON Schema ve conformance

- `schemas/policy-v1.schema.json` ve `schemas/policy-v2.schema.json` üretilir; ikisi de
  JSON Schema draft 2020-12'dir. v2 şeması §14.2 tablosundaki tüm alanları ve
  §14.1'deki sürüm kurallarını içerir.
- Şemalar editör otomatik-tamamlama için yayınlanır ve conformance vektörleriyle
  birlikte sürümlenir.
- Conformance vektörleri `(politika dosyası, girdi) → beklenen verdict + reason` üçlüsü
  dür; her iki sürümün davranışını sabitler. Yükleyici ve karar motoru değişiklikleri bu
  vektörleri geçmek zorundadır.
