# roe-guard — Kapsamlı Proje Spesifikasyonu & Yol Haritası

**Paket adı (çalışma adı):** roe-guard (PyPI: `roe-guard`, import: `roe_guard`)
**Marka:** 0rce Labs
**Lisans (öneri):** MIT — geniş benimseme ve entegrasyon kolaylığı için
**Durum:** v0.1 planlama aşaması, kod henüz yazılmadı

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
- Policy dosyaları için JSON Schema + editör otomatik-tamamlama desteği

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
