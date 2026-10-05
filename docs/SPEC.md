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
| T13 | Public API export + `Engagement.from_file` | Kök paket public API'yi `__all__` ile dışa verir; `Engagement.from_file()` çalışır. |
| T14 | `schema_version` kapısı | `schema_version` alanı ve `MAX_SCHEMA_VERSION` kapısı; desteklenmeyen sürüm `PolicyParseError` ile reddedilir (§5, §14.1). |
| T15 | v2 bilinmeyen anahtar reddi | v2'de bilinmeyen anahtar her seviyede reddedilir, `x-*` yok sayılır; v1'de v2 blokları reddedilir, diğer bilinmeyenler `UnknownKeyWarning` verir (§5, §14.1). |
| T16 | `py.typed` + mypy | PEP 561 `py.typed` işaretleyicisi; CI'da strict `mypy` adımı. |
| T17 | Coverage eşiği | CI coverage `fail_under` eşiğini zorlar. |
| T18 | Bu SPEC | Politika şeması v2 ve audit kaydı v2 sözleşmesi (§14). |
| T19 | JSON Schema v1 + v2 | `schema/policy.v1.json` ve `schema/policy.v2.json` (§14.1, §14.2, §14.8). |
| T20 | v2 yükleyici + `EnforcementMode` + `reason_code` | `mode`, `sandbox` ve `approval` blokları, kökteki `x-*` → `Policy.extensions`, `parse_policy`, `Policy.source_sha256`, `EnforcementMode`, `ReasonCode`'un ilk 9 üyesi (`POLICY_INVALID` ve adım 1–8 kodları), `Decision.mode`/`reason_code`/`matched_rule` (§14.2, §14.3, §14.6). `agent` ve `egress` blokları bu işte hâlâ reddedilir. |
| T21 | Agent kimlik adımı | `agent` bloğu (`Policy.agent`), `AgentIdentity`, karar merdiveninde adım 0, üç `AGENT_*` kodu ve `Decision.agent_id` (§14.4, §14.6). |
| T22 | `enforce_egress` | `egress` bloğu (`Policy.egress`), `enforce_egress`, `Engagement.check_egress` ve sekiz `EGRESS_*` kodu (§14.5, §14.6). |
| T23 | Conformance vektörleri | `conformance/cases/` vektörleri, vaka şeması ve koşucu (§14.4–§14.6, §14.8). |
| T24 | Audit kaydı v2 | `AuditLogV2`, JCS, checkpoint'ler, v2 zincir doğrulaması, `schema/audit-record.v2.json`, `schema/audit-checkpoint.v2.json`, `conformance/audit/` ve `conformance/jcs/` vektörleri (§14.7, §14.8). |

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

Bu bölüm politika şeması v2'yi ve audit kaydı v2'yi tanımlar. v2 işleri (§10, T19–T24) bu metni
aynen uygular. "Zorlayan platform", roe-guard kararlarını çalışma zamanında uygulayan sistemdir
(ör. bir sandbox altyapısı); roe-guard bu platformun iç ayrıntılarını varsaymaz.

### 14.1 Sürümleme ve anahtar kuralları

- `schema_version` alanı v1'de opsiyoneldir, yoksa `1` sayılır. v2 dosyasında zorunludur ve değeri `2`'dir.
- `MAX_SCHEMA_VERSION = 2`. Şunlar `PolicyParseError(field="schema_version")` ile reddedilir: bundan büyük değer, 1'den küçük değer, `int` olmayan değer (bool dahil) ve `null`. Sürüm kontrolü diğer bütün kontrollerden önce yapılır.
- v1 dosyasında kökte `mode`, `agent`, `sandbox`, `egress` ya da `approval` varsa: `PolicyParseError(field=<anahtar>)`, mesaj `'<anahtar>' requires schema_version: 2`.
- v1'de diğer bilinmeyen anahtarlar `UnknownKeyWarning` ile uyarılır ve yok sayılır.
- v2'de her seviyede bilinmeyen anahtar `PolicyParseError` verir; `field` alanı noktalı yoldur (ör. `egress.http.allow[1].proto`).
- `x-` ile başlayan anahtarlar her seviyede ve her sürümde yok sayılır. Kökteki `x-*` anahtarları `Policy.extensions` sözlüğüne konur. Üreticiye özgü alanlar yalnız `x-<üretici>` altında yaşar; roe-guard bunların içeriğini yorumlamaz.
- §14'teki bütün düzenli ifadeler dizenin tamamına ve ASCII anlamıyla uygulanır (Python'da `re.fullmatch(..., flags=re.ASCII)`); `\d` yalnız `0-9`'dur. Sondaki satır sonu dahil fazladan karakter eşleşmeyi bozar.
- Hata `field` kuralları: bilinmeyen anahtarda anahtarın yolu, eksik zorunlu anahtarda eksik anahtarın yolu (ör. `approval.timeout_seconds`), tip ya da değer hatasında değerin yolu (ör. `egress.http.allow[0].ports[0]`). v1'in mevcut `field` değerleri değişmez; ör. kökteki eksik alanlar için `<top>`.

### 14.2 v2 alanları

Bütün v2 bloklarını içeren örnek:

```yaml
schema_version: 2
engagement_id: "example-2026-10"
valid_from: "2026-10-01T00:00:00Z"
valid_until: "2026-10-31T23:59:59Z"

scope:
  allow:
    - cidr: "192.0.2.0/24"
    - hostname: "*.staging.example.org"
  deny:
    - cidr: "192.0.2.128/25"

actions:
  allow: ["recon", "scan"]
  deny: ["destructive"]

blackout_windows:
  - start: "2026-10-15T00:00:00Z"
    end: "2026-10-16T00:00:00Z"
    reason: "bakım penceresi"

approval_required_for: ["scan"]
approvers: ["ops-lead@example.com"]

mode: observe

agent:
  id: "spiffe://example.org/agents/research-*"
  runtime: ["example-runtime"]

sandbox:
  filesystem:
    read: ["/workspace/**"]
    write: ["/workspace/out/**"]
    deny: ["/workspace/.secrets/**"]
  syscalls:
    profile: "default"
    deny: ["ptrace", "mount"]
  resources:
    pids_max: 256
    memory_max: "2G"
    cpu_max: "100000 100000"
  credentials:
    max_ttl_seconds: 900
  imds: deny

egress:
  default: deny
  http:
    allow:
      - host: "*.example.com"
        ports: [443]
        methods: ["GET", "POST"]
      - cidr: "198.51.100.0/24"
        ports: [443, 8443]
    deny:
      - host: "uploads.example.com"
  dns:
    allow: ["*.example.com"]
    deny: ["uploads.example.com"]
    record_types: ["A", "AAAA"]

approval:
  timeout_seconds: 600
  on_timeout: deny

x-vendor:
  change_ticket: "CHG-0001"
```

| Alan | Tip | Zorunlu | Varsayılan | Kural |
|---|---|---|---|---|
| `schema_version` | int | v2'de evet | 1 | `2` |
| `engagement_id`, `valid_from`, `valid_until`, `scope`, `actions`, `blackout_windows`, `approval_required_for`, `approvers` | v1 ile aynı | v1 ile aynı | v1 ile aynı | v1 ile aynı; bu alanlarda `null` liste v1'deki gibi `[]` sayılır |
| `mode` | str | hayır | `enforce` | `enforce` ya da `observe` |
| `agent.id` | str | blok varsa evet | — | `spiffe://` ile başlar; glob (`fnmatch.fnmatchcase`, büyük/küçük harf duyarlı) |
| `agent.runtime` | [str] | hayır | `[]` | boş olmayan dizeler |
| `sandbox.filesystem.read` / `.write` / `.deny` | [str] | hayır | `[]` | boş olmayan glob dizeleri |
| `sandbox.syscalls.profile` | str | hayır | — | boş olmayan |
| `sandbox.syscalls.deny` | [str] | hayır | `[]` | boş olmayan |
| `sandbox.resources.pids_max` | int | hayır | — | ≥ 1, bool değil |
| `sandbox.resources.memory_max` / `.cpu_max` | str | hayır | — | boş olmayan; biçimi zorlayan platform yorumlar |
| `sandbox.credentials.max_ttl_seconds` | int | hayır | — | ≥ 1, bool değil |
| `sandbox.imds` | str | hayır | `deny` | yalnız `deny` |
| `egress.default` | str | hayır | `deny` | yalnız `deny` (fail-open ifade edilemez) |
| `egress.http.allow[]` | nesne | hayır | `[]` | `host` (glob) ya da `cidr`'den tam olarak biri; `ports` zorunlu, en az 1 eleman, her biri 1..65535; `methods` opsiyonel, verilirse en az 1 eleman, her biri `^[A-Z]+$` |
| `egress.http.deny[]` | nesne | hayır | `[]` | `host` ya da `cidr`'den tam olarak biri |
| `egress.dns.allow` / `.deny` | [str] | hayır | `[]` | boş olmayan alan adı glob'ları |
| `egress.dns.record_types` | [str] | hayır | `[A, AAAA]` | `A`, `AAAA`, `CNAME`; tekrarsız, en az 1 |
| `approval.timeout_seconds` | int | blok varsa evet | — | ≥ 1, bool değil |
| `approval.on_timeout` | str | hayır | `deny` | yalnız `deny` |

Notlar:

- v2'nin yeni bloklarında `null` liste kabul edilmez.
- `sandbox`, `egress.dns` ve `approval` blokları roe-guard'da yalnız doğrulanır. Zorlanmaları politikayı uygulayan platformun işidir.
- `approvers` hâlâ kullanılmaz.

### 14.3 Modlar

- `EnforcementMode(str, Enum)`: `ENFORCE = "enforce"`, `OBSERVE = "observe"`. `DecisionType`'tan ayrıdır; `DecisionType` üç üyede kalır.
- `enforce`: DENY aksiyonu engeller. REQUIRES_APPROVAL onay gelene kadar bekletilir; `approval.timeout_seconds` dolarsa sonuç DENY olur.
- `observe`: Verdict hesaplanır ve kaydedilir, aksiyon geçirilir. DENY'ler yine deneme sinyalidir.
- Sert taban her modda zorlanır. Şu iki durum observe modunda da engeller:
  - `EGRESS_IMDS_DENIED` (instance metadata servisi ve link-local çıkış).
  - `POLICY_INVALID` (politika yüklenemedi; mod da bilinmez).
- roe-guard'ın kendi yardımcıları moddan bağımsızdır ve verdict'e göre davranır (fail-closed): `guarded`, `Decision.raise_if_denied`, `window` ve CLI `check` çıkış kodu (0/1/2). Observe davranışını zorlayan platform uygular.
- Her `Decision` politikanın modunu `mode` alanında taşır.

### 14.4 Karar merdiveni v2

İmzalar:

- `enforce(engagement, target, action_type, now=None, metadata=None, *, agent=None)`.
- `Engagement.check(target, action_type, now=None, *, agent=None)`.
- `guarded(engagement, action_type, target_arg="target", *, agent=None)`.
- `AgentIdentity(id: str, runtime: str | None = None)`.

Adım 0 yalnız politikada `agent` bloğu varsa çalışır ve adım 1'den önce gelir. Adım 1–8'in
sırası, verdict'i ve `reason` metni v1 ile (§5) birebir aynıdır; yalnız `reason_code` ve
`matched_rule` eklenir.

| Adım | Koşul | Verdict | `reason_code` | `matched_rule` | `reason` |
|---|---|---|---|---|---|
| 0a | `agent` yok ya da `agent.id == ""` | DENY | `AGENT_ID_MISSING` | `agent.id` | `agent identity missing` |
| 0b | `agent.id` desenle eşleşmiyor | DENY | `AGENT_ID_MISMATCH` | `agent.id` | `agent identity does not match policy` |
| 0c | `agent.runtime` listesi boş değil ve çağıranın runtime'ı `None` ya da listede yok | DENY | `AGENT_RUNTIME_NOT_ALLOWED` | `agent.runtime` | `agent runtime not allowed` |
| 1 | `not (valid_from <= now < valid_until)` | DENY | `POLICY_NOT_ACTIVE` | `valid_from/valid_until` | `policy expired or not yet active` |
| 2 | `now` bir blackout penceresinde | DENY | `BLACKOUT_WINDOW` | `blackout_windows[<i>]` | `inside blackout window[: <reason>]` |
| 3 | hedef `scope.deny` ile eşleşiyor | DENY | `TARGET_DENIED` | `scope.deny[<i>]` (ilk eşleşen) | `target explicitly denied in scope` |
| 4 | hedef hiçbir `scope.allow` ile eşleşmiyor | DENY | `TARGET_NOT_IN_SCOPE` | `scope.allow` | `target not in allowed scope` |
| 5 | `action_type`, `actions.deny` içinde | DENY | `ACTION_DENIED` | `actions.deny` | `action type '<a>' explicitly denied` |
| 6 | `action_type`, `approval_required_for` içinde | REQUIRES_APPROVAL | `APPROVAL_REQUIRED` | `approval_required_for` | `action type '<a>' requires human approval` |
| 7 | `action_type`, `actions.allow` içinde | ALLOW | `ACTION_ALLOWED` | `actions.allow` | `action type '<a>' allowed` |
| 8 | hiçbiri | DENY | `ACTION_NOT_ALLOWED` | boş dize (`""`) | `action type not explicitly allowed` |

Tablodaki `<a>`, `<i>` ve `<reason>` yer tutucudur. `'<a>'`, v1'deki gibi `action_type`'ın Python
`repr()` çıktısıdır; `<reason>` blackout penceresinin `reason` değeridir ve boşsa `: <reason>` eki
yazılmaz.

Eşleştirme kuralları:

- `agent.id` glob'u `fnmatch.fnmatchcase` ile, büyük/küçük harfe duyarlı karşılaştırılır; `*` `/` karakterini de kapsar.
- Scope eşleştirmesi v1 ile aynıdır: `cidr` yalnız IP literal hedefle eşleşir; `hostname` küçük harfe çevrilmiş dizelerde `fnmatchcase` kullanır ve ad çözülmez.
- `action_type` tam ve büyük/küçük harfe duyarlı eşleşir.

### 14.5 enforce_egress

İmzalar:

- `enforce_egress(engagement, host, port, method=None, *, now=None, agent=None) -> Decision`.
- `Engagement.check_egress(host, port, method=None, *, now=None, agent=None)`.

Dönen `Decision`'da `target` = `host:port`'tur; IPv6 hedefte `[host]:port`. `action_type` =
`egress`'tir; method verilmişse `egress:<METHOD>`.

`scope` ve `actions` egress'e uygulanmaz. Sıra sabittir ve ilk eşleşme kazanır.

| Adım | Koşul | Verdict | `reason_code` | `matched_rule` | `reason` |
|---|---|---|---|---|---|
| E0 | §14.4 adım 0 (yalnız `agent` bloğu varsa) | DENY | `AGENT_*` | §14.4 gibi | §14.4 gibi |
| E1 | zaman penceresi dışı | DENY | `POLICY_NOT_ACTIVE` | `valid_from/valid_until` | `policy expired or not yet active` |
| E2 | blackout | DENY | `BLACKOUT_WINDOW` | `blackout_windows[<i>]` | `inside blackout window[: <reason>]` |
| E3 | host/port/method geçersiz | DENY | `EGRESS_TARGET_INVALID` | boş dize (`""`) | `egress target invalid` |
| E4 | IMDS / link-local hedef | DENY | `EGRESS_IMDS_DENIED` | boş dize (`""`) | `egress to instance metadata or link-local address denied` |
| E5 | politikada `egress` bloğu yok | DENY | `EGRESS_NOT_CONFIGURED` | `egress` | `egress not configured in policy` |
| E6 | hedef bir `egress.http.deny` girdisiyle eşleşiyor | DENY | `EGRESS_HOST_DENIED` | `egress.http.deny[<i>]` | `egress host explicitly denied` |
| E7 | hedef hiçbir `egress.http.allow` girdisiyle eşleşmiyor | DENY | `EGRESS_HOST_NOT_ALLOWED` | `egress.http.allow` | `egress host not allowed` |
| E8 | hedefle eşleşen girdilerin hiçbirinde `port` yok | DENY | `EGRESS_PORT_NOT_ALLOWED` | hedefle eşleşen ilk girdi `egress.http.allow[<i>]` | `egress port not allowed` |
| E9 | host ve port eşleşen girdilerin hepsinde `methods` var ve `method` `None` ya da listede yok | DENY | `EGRESS_METHOD_NOT_ALLOWED` | host+port eşleşen ilk girdi | `egress method not allowed` |
| E10 | aksi halde | ALLOW | `EGRESS_ALLOWED` | tam eşleşen ilk girdi `egress.http.allow[<i>]` | `egress allowed` |

**E3 doğrulaması:**

- `host` boş olmayan bir `str` olmalıdır.
- `ipaddress.ip_address(host)` başarılıysa hedef IP literal'dir. Köşeli parantezli yazım (`[2001:db8::1]`) geçersizdir.
- Değilse hedef bir addır. Önce küçük harfe çevrilir ve sondaki tek `.` atılır. Toplam uzunluk 1–253 olmalıdır. Her etiket `^([a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$` ile eşleşmelidir. Son etiket `^(0x[0-9a-f]*|[0-9]+)$` ile eşleşmemelidir. Bu kural, kanonik olmayan sayısal IP yazımlarının (tam sayı, sekizlik, onaltılık) ad olarak kabul edilmesini engeller.
- `port` bool olmayan bir `int` olmalı ve 1..65535 aralığında kalmalıdır.
- `method` `None` ya da boş olmayan bir `str` olmalıdır.

**E4 listesi:**

- `169.254.0.0/16`, `168.63.129.16`, `100.100.100.200`, `fe80::/10` ve `fd00:ec2::254`.
- Eşlenen IPv4 adresi bu IPv4 girdilerinden birine düşen IPv4-mapped IPv6 adresler (`::ffff:169.254.x.y`, `::ffff:168.63.129.16`, `::ffff:100.100.100.200`).
- Normalleştirilmiş adlar `metadata.google.internal`, `metadata` ve `instance-data` (bulut arama alan adlarıyla metadata servisine çözülen kısa adlar).
- Bu adım allow kurallarından önce gelir ve politika ne derse desin uygulanır.

**Eşleştirme:**

- `host` glob'ları yalnız ad hedefleriyle eşleşir; küçük harfe çevrilmiş dizelerde `fnmatchcase` kullanılır. Desen de hedef gibi normalleştirilir: küçük harfe çevrilir ve sondaki tek `.` atılır.
- `cidr` girdileri yalnız IP literal hedeflerle eşleşir. `::ffff:0:0/96` içinde yazılmış bir `cidr` girdisi IPv4 karşılığı olarak okunur (önek − 96). IPv4-mapped IPv6 hedef (`::ffff:a.b.c.d`) `allow` girdileriyle yalnız eşlendiği IPv4 adresi olarak, `deny` girdileriyle hem bu IPv4 adresi hem IPv6 adresi olarak eşleştirilir. Böylece bir IPv4 adresi için yazılmış `deny` girdisi (IPv4 ya da `::ffff:0:0/96` içinde) hiçbir yazımla atlatılamaz ve `::/0` gibi bir IPv6 `allow` girdisi IPv4 izin listesini genişletemez. `::/0` gibi daha geniş bir IPv6 `deny` girdisi IPv6 yazımlı hedefleri (IPv4-mapped dahil) kapsar, IPv4 yazımlı hedefleri kapsamaz.
- `methods` karşılaştırması tam ve büyük/küçük harfe duyarlıdır.
- `egress.http` yoksa allow listesi boş sayılır ve sonuç E7 olur.

**Ad çözümleme yapılmaz.** Zorlayan platform `enforce_egress`'i hem adla hem de bağlanılan IP ile
çağırmalı ve ikisinin de ALLOW olmasını beklemelidir.

`egress.dns` bloğu roe-guard'da yalnız doğrulanır. Semantiği platformun resolver'ı uygular:
`deny` > `allow` > varsayılan DENY; `record_types` dışındaki sorgu tipi DENY.

### 14.6 Yeni alanlar ve uyumluluk kuralları

- `ReasonCode(str, Enum)`: her üyenin değeri adıyla aynıdır. Üyeler §14.4 ve §14.5'teki 19 kod ile `POLICY_INVALID`'dir; toplam 20.
- `POLICY_INVALID`'in anlamı: politika yüklenemedi. Çağıran taraf bu durumda her girdiyi DENY sayar ve bu durum observe modunda da engeller.
- `parse_policy(raw: Mapping[str, Any]) -> Policy` dosyasız ayrıştırmadır. `load_policy(path)` dosyanın ham baytlarından `Policy.source_sha256` değerini de hesaplar.
- `Decision`'a sona ve varsayılanla eklenen alanlar: `mode: EnforcementMode = ENFORCE`, `reason_code: str = ""`, `matched_rule: str = ""`, `agent_id: str = ""`.
- `Policy`'ye sona ve varsayılanla eklenen alanlar: `schema_version=1`, `mode=ENFORCE`, `sandbox=None`, `approval=None`, `extensions={}`, `source_sha256=""`, `agent=None`, `egress=None`.
- Uyumluluk kuralları:
  - (a) Her geçerli v1 dosyası v2 kodunda aynı verdict'i ve aynı `reason`'ı üretir. Bunu altın conformance vektörleri kanıtlar.
  - (b) Her yeni blok opsiyoneldir; blok yoksa davranış v1 ile aynıdır.
  - (c) `DecisionType` üç üyede kalır. Yeni alanlar sona ve varsayılanla eklenir, konumsal kurulum bozulmaz.
  - (d) Mevcut imzalar değişmez; yeni parametreler keyword-only'dir. Egress kontrolü ayrı bir fonksiyondur. 8 adımlı merdivendeki tek ek, opsiyonel adım 0'dır.
  - (e) Audit v2 kayıtları §14.7'dedir. Karışık v1→v2 zincirleri doğrulanır.
  - (f) JSON Schema dosyaları ve dil bağımsız conformance paketi §14.8'dedir. Başka dillerdeki değerlendiriciler aynı vektörleri geçmek zorundadır.

### 14.7 Audit kaydı v2

Dosya JSONL'dir ve UTF-8 kodludur. Her satır, kaydın (`entry_hash` dahil) JCS çıktısı ve
ardından gelen `\n`'dir. Kayıtta tam olarak şu 16 anahtar bulunur:

| Alan | Kural |
|---|---|
| `v` | int, sabit `2` |
| `seq` | int ≥ 0; zincirdeki kayıt sırası; v1 satırları da sayılır; 0'dan başlar, her kayıtta +1 |
| `chain_id` | `^[A-Za-z0-9._:-]{1,128}$`; zincir boyunca sabit |
| `timestamp` | `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$` (UTC, 6 hane kesir, `Z`); ham dize hash'lenir, yeniden ayrıştırılmaz |
| `engagement_id` | boş olmayan dize |
| `policy_sha256` | `^[0-9a-f]{64}$`; kararın verildiği politika dosyasının ham baytlarının SHA-256'sı (`Policy.source_sha256`) |
| `mode` | `enforce` ya da `observe` |
| `agent_id` | dize; kimlik yoksa `""` |
| `target`, `action_type`, `reason`, `reason_code` | dize |
| `decision` | `ALLOW`, `DENY` ya da `REQUIRES_APPROVAL` |
| `metadata` | nesne (`{}` olabilir); değerleri JCS alt kümesindedir |
| `prev_hash` | 64 küçük harf hex; önceki kaydın `entry_hash`'i; ilk kayıtta `"0"*64`; karışık zincirde ilk v2 kaydı için son v1 satırının `entry_hash`'i |
| `entry_hash` | `sha256(JCS(kayıt − entry_hash))`, küçük harf hex |

**JCS alt kümesi (RFC 8785):**

- İzinli değerler: dize, tamsayı (|n| ≤ 2^53−1), `true`, `false`, `null`, dize anahtarlı nesne, dizi. Kayan noktalı sayı yoktur.
- Anahtarlar UTF-16 kod birimi sırasına göre sıralanır.
- Kısa kaçışlar: `"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`. Diğer U+0000–U+001F karakterleri `\u00xx` biçiminde (küçük hex) yazılır. Geri kalan karakterler ham UTF-8'dir.
- Eşleşmemiş surrogate ve aynı nesnede yinelenen anahtar hatadır.
- İç içe nesne ve dizi derinliği en fazla 64'tür; daha derin değer hatadır.

**Tek yazıcı:**

- `AuditLogV2` dosyayı `fcntl.flock(LOCK_EX | LOCK_NB)` ile kilitler. İkinci yazıcı `AuditWriterLockedError` alır. `fcntl` olmayan platformda yazıcı açılmaz (fail-closed).
- Açılışta mevcut dosya baştan doğrulanır. Dosya geçersizse `AuditIntegrityError` fırlatılır ve hiçbir satır yazılmaz.
- v1 `AuditLog.record()`, v2 satırı içeren bir zincire yazmayı reddeder (`AuditIntegrityError`).

**Checkpoint:**

- Dosya `<audit dosyası>.checkpoints.jsonl`'dir. Her satır tam olarak şu 7 anahtarı içeren nesnenin JCS çıktısıdır: `v` (2), `chain_id`, `seq` (kapsanan son kaydın `seq` değeri), `head_hash` (o kaydın `entry_hash`'i), `timestamp` (aynı biçim), `key_id`, `sig`.
- `key_id` = `sha256:` + ham 32 bayt ed25519 açık anahtarın SHA-256 hex'i.
- `sig`, `JCS(checkpoint − sig)` üzerinde ed25519 imzasıdır; padding'siz base64url, 86 karakter.
- Yazıcıya imzalayıcı verilmişse yazıcı her `checkpoint_every` kayıtta (varsayılan 1000) checkpoint üretir; kapanışta yalnız son checkpoint'ten sonra en az bir kayıt yazılmışsa checkpoint üretir. Checkpoint'ten önce `fsync` yapılır. İmzalayıcı yoksa checkpoint yazılmaz; zincir yalnız hash bağlarıyla korunur (§7 madde 2).
- İmza anahtarını çağıran sağlar. Anahtar saklama ve yayımlama roe-guard'ın kapsamı dışındadır.

**Karışık zincir:** v1 satırlarından sonra v2 satırları gelebilir. v2 satırından sonra v1 satırı
gelirse sonuç `VERSION_DOWNGRADE` olur.

**Satırlar:**

- Satırlar yalnız `\n` ile ayrılır. JCS U+0085, U+2028 ve U+2029'u ham yazar. Bu kural v1 satırları için de geçerlidir: eski v1 okuyucusu tek başına `\r`'yi de satır sonu sayıyordu; v1 yazıcısı `\r` üretmediği için fark yalnız elle değiştirilmiş dosyalarda görülür.
- Sonuç ayrıştırıcının sınırlarına bağlı değildir. Tamsayı literalleri yorumlayıcının basamak sınırından bağımsız okunur. Ayrıştırıcının kendi derinlik sınırını aşan bir değer de aşağıdaki adım sırasıyla değerlendirilir; 64'ten derin iç içelik 5. adımdır.
- v2 satırı ve checkpoint satırı, nesnenin JCS baytları ve `\n`'den ibarettir. Aynı içeriğin başka baytlarla yazılışı (anahtar sırası, boşluk, kaçış, `\r`, son satırda eksik `\n`) v2 satırında `MALFORMED` (5. adım), checkpoint'te `CHECKPOINT_MALFORMED` olur.
- `v` anahtarı olmayan satır v1 satırıdır ve v1 `AuditLog.verify()` kurallarıyla doğrulanır. İlk v2 satırından önceki boş satırlar atlanır. `seq` satırları değil kayıtları sayar.
- Bir v2 satırından sonra gelen boş satır `INVALID_JSON` olur.

**Doğrulama sırası.** v2 satırı için sıra şudur:

1. JSON ayrıştırma (`INVALID_JSON`). Geçersiz UTF-8, `NaN` ve `Infinity` de bu koddur.
2. Yinelenen anahtar ya da eksik anahtar (`MALFORMED`).
3. `v` ≠ 2 (`UNKNOWN_VERSION`).
4. Fazla anahtar (`UNKNOWN_FIELD`).
5. Tip ya da değer hatası (`MALFORMED`). JCS alt kümesi dışındaki değerler (kayan noktalı sayı, sınır dışı tamsayı, eşleşmemiş surrogate, 64'ten derin iç içelik) ve kanonik olmayan satır baytları da bu koddur.
6. Zaman biçimi (`TIMESTAMP_FORMAT`).
7. `chain_id` değişti (`CHAIN_ID_MISMATCH`).
8. `seq` ≠ kayıt sırası (`SEQ_MISMATCH`).
9. `prev_hash` (`PREV_HASH_MISMATCH`).
10. `entry_hash` (`ENTRY_HASH_MISMATCH`).

Checkpoint doğrulaması, doğrulayıcıya bir checkpoint dosyası yolu verildiğinde yapılır. Sıra şudur:

1. Verilen dosya yok ya da hiç checkpoint satırı içermiyor (`CHECKPOINT_MISSING`).
2. Biçim (`CHECKPOINT_MALFORMED`).
3. `chain_id` (`CHAIN_ID_MISMATCH`).
4. Bilinmeyen anahtar kimliği (`CHECKPOINT_KEY_UNKNOWN`).
5. ed25519 desteği yok (`SIGNING_BACKEND_UNAVAILABLE`).
6. İmza (`CHECKPOINT_SIGNATURE_INVALID`).
7. `seq` ≥ kayıt sayısı (`CHAIN_TRUNCATED`).
8. `head_hash` uyuşmuyor (`CHECKPOINT_HEAD_MISMATCH`).

Checkpoint kuralları:

- Her checkpoint'in `head_hash`'i, `seq` konumundaki kaydın `entry_hash`'iyle karşılaştırılır. Son checkpoint'ten sonraki kayıtlar geçerlidir (bilinen sınır).
- Doğrulayıcı checkpoint dosyasını audit dosyasından önce okur. Yazıcı önce kaydı yazıp `fsync` eder, sonra checkpoint'i ekler; bu sırayla çalışan yazıcının yanında doğrulama yanlış `CHAIN_TRUNCATED` vermez.
- `seq` azalmaz; aynı `seq` tekrar edebilir. `sig` kanonik base64url'dir: son karakterin dolgu bitleri sıfırdır. Aksi `CHECKPOINT_MALFORMED` olur.
- Zincirde v2 satırı yoksa bütün checkpoint'lerin `chain_id`'si ilk checkpoint'inkiyle aynı olmalıdır.
- `broken_at_index`: `CHAIN_TRUNCATED`'da kayıt sayısı, `CHECKPOINT_MISSING`'de `null`, diğer kodlarda checkpoint'in `seq` değeridir. Satırda JCS aralığında (≤ 2^53−1) negatif olmayan tamsayı `seq` yoksa değer `null` olur; satır başka bir nedenle (yinelenen anahtar, `NaN`, aşırı derinlik) bozuk olsa da `seq` okunur.

**Doğrulama sonucu:** `AuditVerificationResult` sona eklenen `reason_code: str | None = None`
alanını taşır.

**Bilinen sınır:** Son checkpoint'ten sonraki kayıtların kesilmesi tespit edilemez. Dış çıpa hâlâ
açık karardır (§12).

### 14.8 JSON Schema ve conformance

- Dosyalar: `schema/policy.v1.json`, `schema/policy.v2.json`, `schema/audit-record.v2.json`, `schema/audit-checkpoint.v2.json`. Hepsi JSON Schema draft 2020-12'dir. Şema yapısaldır. Tarih sırası, CIDR geçerliliği ve ISO-8601 ayrıştırması yalnız politika yükleyicisinde yapılır. Desenlerin tam ve ASCII anlamıyla eşleşmesi (§14.1) ve `int` istenen yerde tam sayı değerli kayan noktalı sayının (ör. `2.0`) reddi şemada değil kodda yapılır: politika dosyalarında yükleyicide, audit kayıtlarında ve checkpoint'lerde yazıcıda (`record()`, `checkpoint()`) ve doğrulayıcıda (`verify_chain`). JSON Schema `2.0`'ı tam sayı sayar ve Python `jsonschema` desenleri `re.search` ile uygular.
- `conformance/cases/*.json` dosyalarının biçimi `{"format": 1, "suite": ..., "cases": [{id, description, policy, input, expected: {verdict, reason_code}}]}`.
- `conformance/audit/` ve `conformance/jcs/` audit v2 ve JCS vektörlerini içerir.
- Tüketiciler vektörleri roe-guard commit SHA'sıyla sabitler. Bilinmeyen `format` değeri tüketicide hatadır.
