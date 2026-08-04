# roe-guard

[![CI](https://github.com/0rce-Labs/roe-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/0rce-Labs/roe-guard/actions/workflows/ci.yml)
[![Python ≥ 3.10](https://img.shields.io/badge/python-%E2%89%A53.10-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Rules of Engagement policy-enforcement library — scope, gate, log, clean.**

**Rules of Engagement politika-zorlama kütüphanesi — kapsam, kapı, günlük, temiz.**

---

## English

### What it is

roe-guard is a small Python library that turns a YAML policy file into a
set of guardrails your code can ask before acting.

You declare *which targets* an operation may touch, *which action
types* count as in-scope, and *when* the operation is valid. Every call
you route through roe-guard gets a clean ALLOW / DENY / REQUIRES_APPROVAL
verdict, and every decision lands in a tamper-evident audit log.

That's it. It doesn't sit on your network, it doesn't intercept packets,
it doesn't pretend to be a firewall. It lives in your code as a function
you call before doing anything risky. If your tool doesn't call it,
roe-guard can't help you — and that's a deliberate trade-off, spelled
out below.

The project is the reference implementation of [0rce Labs](https://github.com/orce-labs)'
*zero-unauthorized-operations* principle. You don't need 0rce to use it.

### Why bother

Scope creep is the single biggest legal and operational risk in a real
pentest or red team engagement. Someone fat-fingers a subnet and pokes at
a production database. An autonomous tool decides "while I'm here" and
touches a system that wasn't contracted. The fallout is rarely pretty.

Most of the time, scope control today is either a human reading the
ruleset before a click — and forgetting once — or an enterprise SOAR
that costs a six-figure sum before you write a single line of useful
code. roe-guard sits in the middle: small enough to drop into any
Python script in two lines, strict enough to be the receipt your
auditors want.

### Install

> **Heads up:** roe-guard is not on PyPI yet. The 0.1.0 release ships
> the trusted-publish pipeline (see `T9` in the changelog); until then
> you install from source. Once it's published, the install drops to
> `pip install roe-guard`.

From source, in editable mode:

```bash
git clone https://github.com/0rce-Labs/roe-guard.git
cd roe-guard
pip install -e ".[dev]"
```

You'll need Python 3.10 or newer. The only runtime dependency is
[`pyyaml`](https://pyyaml.org/).

Sanity check:

```bash
$ roe-guard --version
roe-guard 0.1.0a1
```

### Quick start

A policy is a YAML file. Here's one that's wide enough to be
illustrative without being a thousand lines:

```yaml
engagement_id: "demo-acme-2026-08"
valid_from: "2020-01-01T00:00:00Z"
valid_until: "2030-01-01T00:00:00Z"

scope:
  allow:
    - cidr: "10.20.0.0/16"
    - hostname: "*.staging.acme.internal"
  deny:
    - cidr: "10.20.5.0/24"            # prod DB subnet — explicit carve-out

actions:
  allow: ["recon", "exploit", "persistence-test"]
  deny: ["destructive", "data-exfil"]

approval_required_for: ["persistence-test"]
```

(Tam örnek için `tests/fixtures/demo_policy.yaml`.)

Validate it:

```
$ roe-guard validate tests/fixtures/demo_policy.yaml
✓ Valid policy: demo-acme-2026-08 (2020-01-01T00:00:00+00:00 → 2030-01-01T00:00:00+00:00)
```

Ask the engine a question. Different inputs, different outcomes:

```
$ roe-guard check --target 10.20.3.5 --action recon \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.3.5
action:     recon
outcome:    ALLOW
reason:     action type 'recon' allowed
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 8.8.8.8 --action recon \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     8.8.8.8
action:     recon
outcome:    DENY
reason:     target not in allowed scope
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 10.20.5.7 --action recon \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.5.7
action:     recon
outcome:    DENY
reason:     target explicitly denied in scope
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 10.20.3.5 --action persistence-test \
    --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.3.5
action:     persistence-test
outcome:    REQUIRES_APPROVAL
reason:     action type 'persistence-test' requires human approval
timestamp:  2026-08-10T12:00:00+00:00
```

Exit codes: **0 = ALLOW, 1 = DENY, 2 = REQUIRES_APPROVAL**. The mapping
is on purpose — a shell script wrapping the CLI can decide what to do
based on `$?` without parsing the human-readable output.

From Python, the same flow:

```python
from roe_guard.policy import load_policy
from roe_guard.models import Engagement

policy = load_policy("tests/fixtures/demo_policy.yaml")
engagement = Engagement(policy=policy)

decision = engagement.check("10.20.3.5", "recon")
print(decision.outcome)  # DecisionType.ALLOW

engagement.check("8.8.8.8", "recon").raise_if_denied()
# → OutOfScopeError: Denied: target='8.8.8.8' action='recon' reason=target not in allowed scope
```

If you've got an existing function you don't want to restructure, drop a
decorator on it:

```python
from roe_guard.integrations.decorator import guarded


@guarded(engagement, action_type="recon", target_arg="host")
def scan(host: str) -> str:
    return f"scanned:{host}"


scan("10.20.3.5")  # → "scanned:10.20.3.5"
scan("8.8.8.8")  # → OutOfScopeError. The body of `scan` never runs.
```

Or scope a whole block:

```python
from roe_guard.exceptions import OutOfScopeError

with engagement.window():
    for host in discovered_hosts:
        engagement.check(host, "recon").raise_if_denied()
        scan(host)
```

The window context manager checks the policy's time range once on entry
and lets you place scope checks however you like inside the block.

If you want a paper trail, write to the audit log:

```python
from roe_guard.audit import AuditLog

audit = AuditLog("/var/log/roe-guard.jsonl")
for host, action in [("10.20.3.5", "recon"), ("8.8.8.8", "recon")]:
    audit.record(engagement.check(host, action), engagement_id=policy.engagement_id)
```

Every entry is chained to the previous one via SHA-256. Verify it from
the CLI:

```
$ roe-guard audit-verify /var/log/roe-guard.jsonl
✓ Audit chain valid (2 entries)
```

If anyone (or anything) inserts, deletes, or modifies a line without
re-hashing the chain, `audit-verify` will tell you exactly which line
broke.

### The CLI at a glance

| Subcommand       | What it does                                  | Exit codes                          |
|------------------|-----------------------------------------------|-------------------------------------|
| `validate`       | Parse and schema-check a YAML policy.         | `0` valid, `1` invalid              |
| `check`          | Evaluate one `(target, action)` pair.         | `0` ALLOW, `1` DENY, `2` REQ-APPROVAL|
| `audit-verify`   | Recompute and verify the hash chain.          | `0` intact, `1` broken              |

Run any of them with `--help` for options. The `--now` flag on `check`
overrides the system clock — handy for tests and for replaying an
incident at a specific time.

### How the engine decides

The decision pipeline is a fixed eight-step ladder, evaluated in order.
First match wins:

1. Now before `valid_from` or after `valid_until` → **DENY**.
2. Now inside any `blackout_windows` entry → **DENY**.
3. Target matches anything in `scope.deny` → **DENY** (deny trumps allow).
4. Target doesn't match anything in `scope.allow` → **DENY**.
5. Action type is in `actions.deny` → **DENY**.
6. Action type is in `approval_required_for` → **REQUIRES_APPROVAL**.
7. Action type is in `actions.allow` → **ALLOW**.
8. Anything else → **DENY** (fail-closed default).

There's no way to phrase a policy that skips a step or reverses the
order — and that's deliberate. The order is the security contract.

### Architecture

```
Policy YAML  →  load_policy()      →  Policy
                                       ↓
                          Engagement (policy + operation)
                                       ↓
              enforce(eng, target, action) → Decision
                                       ↓
                          audit.record() → JSONL + SHA-256 chain
```

Modules, in one line each:

- `models`      — Immutable `Policy`, `Engagement`, `Decision`, `AuditEntry` dataclasses.
- `policy`      — YAML loading and schema validation (uses `yaml.safe_load`, never `unsafe`).
- `engine`      — The eight-step ladder above.
- `audit`       — Append-only JSONL with SHA-256 hash chaining.
- `integrations` — `@guarded` decorator and `engagement.window()` context manager.
- `cli`         — Three subcommands, stdlib `argparse`, no third-party CLI framework.
- `exceptions`  — `OutOfScopeError`, `PolicyExpiredError`, `PolicyParseError`, `AuditIntegrityError`, `ApprovalRequiredError`.

One runtime dependency: **pyyaml**. The full design lives in
[`docs/SPEC.md`](docs/SPEC.md).

### Threat model and honest limits

roe-guard is a security primitive, so the limits matter more than the
features. Don't skip this section.

1. **It is not a firewall.** roe-guard only constrains code that calls
   `enforce()` or `@guarded`. A tool that doesn't opt in can do
   anything it likes; roe-guard never sees it. This is an SDK-level
   discipline layer, not a network-level enforcement.
2. **The audit log detects tampering; it doesn't prevent it.** Hash
   chaining catches after-the-fact edits and deletions. It cannot stop
   an attacker who has filesystem write access from deleting the file
   outright or re-writing it from scratch.
3. **The policy file is trusted input.** `safe_load` rules out RCE from
   YAML, but if someone can rewrite the file on disk, the scope is
   effectively whatever they rewrote it to be. File permissions are
   your problem.
4. **Fail-closed, fail-loud.** A policy that can't be parsed, has
   expired, or is ambiguous denies everything. If you see roe-guard
   returning DENY a lot, that's the library telling you to fix your
   configuration, not a bug.

These limits are a design choice, not a defect. A small, auditable
library that does one thing well beats a Swiss army knife that does
five things shoddily.

### Development

```bash
pytest                          # run the full test suite
pytest tests/test_engine.py -v  # just the decision engine
ruff check .                    # lint
ruff format --check .           # format check
```

Test coverage target from the spec is ≥85%. The matrix in CI runs the
suite on Python 3.10 through 3.13.

### License

MIT — see [LICENSE](LICENSE).

Built by [0rce Labs](https://github.com/orce-labs).
Full design notes and the v0.2/v0.3 roadmap live in
[`docs/SPEC.md`](docs/SPEC.md).

---

> **Branch protection:** the `main` branch is locked down. All changes
> land through a feature branch named `ticket/T<N>-<slug>` and a pull
> request. CI must pass before merge. Commit messages follow
> `[T<N>] <description>`. Set this up under
> *Settings → Branches → Branch protection rules* on the GitHub side.

---

## Türkçe

### Nedir bu?

roe-guard küçük bir Python kütüphanesi. Tek yaptığı şey: bir YAML
politika dosyasını alıp, kodun içinden "şu hedefe şu aksiyonu
atabilir miyim?" diye sorabileceğiniz küçük bir koruma katmanına
çevirmek.

Nereye dokunulabilir, hangi aksiyon tipleri kapsamda, ne zaman
geçerli — hepsi tek dosyada. Her sorunuza temiz bir ALLOW / DENY /
REQUIRES_APPROVAL kararıyla yanıt veriyor; verdiği her karar da
tahrif edilemez bir log'a düşüyor.

Bu kadar. Ağınıza oturmuyor, paketleri yakalamıyor, firewall değil.
Kodunuzun içinde, riskli bir şey yapmadan önce çağırdığınız sıradan
bir fonksiyon. Aracınız onu çağırmıyorsa yapabileceği bir şey yok —
bu bilinçli bir tercih, nedenlerini aşağıda uzun uzun anlattım.

Proje, [0rce Labs](https://github.com/orce-labs)'ın
*sıfır-yetkisiz-operasyon* ilkesinin referans uygulaması.
Kullanmak için 0rce'ye ihtiyacınız yok.

### Neden uğraşalım?

Scope creep — yani kapsam dışına kayma — gerçek bir pentest ya da
red team operasyonundaki en büyük hukuki ve operasyonel risk. Biri
bir subnet'i yanlış yazar, prod veritabanını kurcalamış olursunuz.
Ya da otonom bir araç "madem buradayım" deyip sözleşmede olmayan bir
sisteme uzanır. Sonucu pek güzel olmuyor.

Bugün kapsam kontrolü çoğu yerde ya operasyondan önce kuralları
okuyup sonra unutan bir insana emanet, ya da tek satır kod yazmadan
önce altı haneli fiyat etiketi olan bir SOAR platformuna. roe-guard
ortada bir yerde duruyor: herhangi bir Python scriptine iki satırla
eklenebilecek kadar küçük, denetçinizin isteyeceği makbuz
niteliğinde olacak kadar sıkı.

### Kurulum

> **Not:** roe-guard henüz PyPI'da değil. 0.1.0 sürümü trusted
> publishing hattını da birlikte çıkaracak (`T9` changelog'a bak);
> o zamana kadar kaynaktan kuruyorsunuz. Yayınlandığında ise
> `pip install roe-guard`'a düşecek.

Kaynaktan, geliştirme modunda:

```bash
git clone https://github.com/0rce-Labs/roe-guard.git
cd roe-guard
pip install -e ".[dev]"
```

Python 3.10 ya da üstü lazım. Çalışma zamanındaki tek bağımlılık
[`pyyaml`](https://pyyaml.org/).

Çalıştığını doğrulayın:

```bash
$ roe-guard --version
roe-guard 0.1.0a1
```

### Hızlı başlangıç

Politika dediğim şey bir YAML dosyası. Burada göstereceğim örnek
bin satıra çıkmadan içinde yeterince şey barındıran bir örnek:

```yaml
engagement_id: "demo-acme-2026-08"
valid_from: "2020-01-01T00:00:00Z"
valid_until: "2030-01-01T00:00:00Z"

scope:
  allow:
    - cidr: "10.20.0.0/16"
    - hostname: "*.staging.acme.internal"
  deny:
    - cidr: "10.20.5.0/24"            # prod DB subnet — bilinçli dışlama

actions:
  allow: ["recon", "exploit", "persistence-test"]
  deny: ["destructive", "data-exfil"]

approval_required_for: ["persistence-test"]
```

(`tests/fixtures/demo_policy.yaml` içinde bunun biraz daha
genişletilmiş hali var.)

Doğrulayın:

```
$ roe-guard validate tests/fixtures/demo_policy.yaml
✓ Valid policy: demo-acme-2026-08 (2020-01-01T00:00:00+00:00 → 2030-01-01T00:00:00+00:00)
```

Şimdi motora bir soru soralım. Girdi değişiyor, karar da değişiyor:

```
$ roe-guard check --target 10.20.3.5 --action recon     --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.3.5
action:     recon
outcome:    ALLOW
reason:     action type 'recon' allowed
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 8.8.8.8 --action recon     --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     8.8.8.8
action:     recon
outcome:    DENY
reason:     target not in allowed scope
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 10.20.5.7 --action recon     --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.5.7
action:     recon
outcome:    DENY
reason:     target explicitly denied in scope
timestamp:  2026-08-10T12:00:00+00:00
```

```
$ roe-guard check --target 10.20.3.5 --action persistence-test     --policy tests/fixtures/demo_policy.yaml --now 2026-08-10T12:00:00Z
target:     10.20.3.5
action:     persistence-test
outcome:    REQUIRES_APPROVAL
reason:     action type 'persistence-test' requires human approval
timestamp:  2026-08-10T12:00:00+00:00
```

Çıkış kodları: **0 = ALLOW, 1 = DENY, 2 = REQUIRES_APPROVAL**. Bu
eşleme bilinçli: CLI'yi saran bir shell scripti, insan-okunur
çıktıyı parse etmeden `$?`'a bakıp kararını verebilsin diye.

Aynı şey Python'da:

```python
from roe_guard.policy import load_policy
from roe_guard.models import Engagement

policy = load_policy("tests/fixtures/demo_policy.yaml")
engagement = Engagement(policy=policy)

karar = engagement.check("10.20.3.5", "recon")
print(karar.outcome)  # DecisionType.ALLOW

engagement.check("8.8.8.8", "recon").raise_if_denied()
# → OutOfScopeError: Denied: target='8.8.8.8' action='recon' reason=target not in allowed scope
```

Yapısını bozmak istemediğiniz mevcut bir fonksiyon varsa dekoratör
düşer:

```python
from roe_guard.integrations.decorator import guarded


@guarded(engagement, action_type="recon", target_arg="host")
def scan(host: str) -> str:
    return f"scanned:{host}"


scan("10.20.3.5")  # → "scanned:10.20.3.5"
scan("8.8.8.8")  # → OutOfScopeError. `scan`'ın gövdesi hiç çalışmaz.
```

Bir de bütün bloğu kapsam altına alabilirsiniz:

```python
from roe_guard.exceptions import OutOfScopeError

with engagement.window():
    for host in discovered_hosts:
        engagement.check(host, "recon").raise_if_denied()
        scan(host)
```

`window` context manager'ı bloğa girerken politikanın tarih aralığını
bir kez kontrol ediyor; içeride kendi kontrollerinizi istediğiniz
gibi yerleştirebilirsiniz.

İz bırakmak istiyorsanız audit log'a yazın:

```python
from roe_guard.audit import AuditLog

audit = AuditLog("/var/log/roe-guard.jsonl")
for host, action in [("10.20.3.5", "recon"), ("8.8.8.8", "recon")]:
    audit.record(engagement.check(host, action), engagement_id=policy.engagement_id)
```

Her entry, bir öncekinin SHA-256 hash'ine zincirleniyor. CLI'dan
doğrulamak için:

```
$ roe-guard audit-verify /var/log/roe-guard.jsonl
✓ Audit chain valid (2 entries)
```

Biri (ya da bir şey) zinciri güncellemeden bir satırı değiştirirse
ya da silerse, `audit-verify` size tam olarak hangi satırın
bozulduğunu söylüyor.

### CLI'a hızlı bakış

| Alt komut       | Ne yapar                                | Çıkış kodları                        |
|-----------------|-----------------------------------------|--------------------------------------|
| `validate`      | YAML politika dosyasını parse + şema.   | `0` geçerli, `1` geçersiz            |
| `check`         | Tek bir `(target, action)` çiftini sına. | `0` ALLOW, `1` DENY, `2` REQ-APPROVAL |
| `audit-verify`  | Hash zincirini yeniden hesapla, doğrula. | `0` sağlam, `1` bozuk                |

Seçenekler için `--help`. `check`'teki `--now` bayrağı sistem
saatini geçersiz kılıyor — testlerde ya da bir olayı belirli bir
anda yeniden oynatmak istediğinizde işe yarıyor.

### Motor nasıl karar veriyor?

Karar hattı sekiz basamaklı, sırası sabit bir merdiven. Yukarıdan
aşağıya değerlendiriliyor; ilk eşleşen kazanıyor:

1. Şu an `valid_from`'dan önce ya da `valid_until`'den sonra → **DENY**.
2. Şu an herhangi bir `blackout_windows` aralığındaysa → **DENY**.
3. Hedef `scope.deny`'deki bir entry ile eşleşiyorsa → **DENY** (deny her zaman allow'u ezer).
4. Hedef `scope.allow`'daki hiçbir entry ile eşleşmiyorsa → **DENY**.
5. Aksiyon tipi `actions.deny`'deyse → **DENY**.
6. Aksiyon tipi `approval_required_for`'daysa → **REQUIRES_APPROVAL**.
7. Aksiyon tipi `actions.allow`'daysa → **ALLOW**.
8. Hiçbiri değilse → **DENY** (fail-closed varsayılan).

Bu sırayı atlayan ya da tersine çeviren bir politika yazmanız mümkün
değil. Bilinçli bir tercih: sıra, güvenlik sözleşmesinin kendisi.

### Mimari

```
YAML politika  →  load_policy()    →  Policy
                                    ↓
                        Engagement (policy + operation)
                                    ↓
            enforce(eng, target, action) → Decision
                                    ↓
                        audit.record() → JSONL + SHA-256 zincir
```

Modüller, tek satırda:

- `models`        — `frozen` `Policy`, `Engagement`, `Decision`, `AuditEntry` dataclass'ları.
- `policy`        — YAML yükleme ve şema doğrulama (`yaml.safe_load`, başka şansı yok).
- `engine`        — Yukarıdaki sekiz basamaklı merdiven.
- `audit`         — SHA-256 zincirli, yalnızca eklenebilir JSONL.
- `integrations`  — `@guarded` dekoratörü ve `engagement.window()` context manager.
- `cli`           — Üç alt komut, stdlib `argparse`, harici bir CLI çatısı yok.
- `exceptions`    — `OutOfScopeError`, `PolicyExpiredError`, `PolicyParseError`, `AuditIntegrityError`, `ApprovalRequiredError`.

Çalışma zamanındaki tek bağımlılık **pyyaml**. Tasarımın tamamı
[`docs/SPEC.md`](docs/SPEC.md) içinde.

### Tehdit modeli ve dürüst sınırlar

roe-guard bir güvenlik aracı; sınırları özelliklerinden daha önemli.
Burayı atlamayın.

1. **Bu bir firewall değil.** roe-guard yalnızca `enforce()` ya da
   `@guarded` çağıran kodu kısıtlıyor. Opt-in yapmayan bir araç
   istediğini yapar; roe-guard onu hiç görmez. Bu SDK seviyesinde
   bir disiplin katmanı. Ağ seviyesinde bir zorlama değil.
2. **Audit log tahrifi *tespit* eder, *engellemez*.** Hash zinciri
   sonradan yapılan ekleme, silme ve değişiklikleri yakalar. Ama
   dosyaya yazma yetkisi olan biri dosyayı komple silebilir ya da
   baştan yazabilir — onu durduramaz.
3. **Politika dosyası güvenilir girdi sayılıyor.** `safe_load`
   RCE'yi kapatıyor. Ama biri dosyayı diskte değiştirebilirse kapsam
   fiilen o kişinin yazdığı şey olmuş oluyor. Dosya izinleri sizin
   işiniz.
4. **Fail-closed, fail-loud.** Parse edilemeyen, süresi dolmuş ya da
   belirsiz politika her şeyi reddeder. roe-guard çok sık DENY
   dönüyorsa bu bir hata değil — kütüphanenin "yapılandırman
   bozuk" diye bağırması.

Bu sınırlar bir tasarım tercihi, eksiklik değil. Tek işi iyi yapan
küçük, denetlenebilir bir kütüphane; beş işi kötü yapan çakı
bıçağından iyidir.

### Geliştirme

```bash
pytest                          # tüm testler
pytest tests/test_engine.py -v  # sadece karar motoru
ruff check .                    # lint
ruff format --check .           # format kontrolü
```

Spec'teki coverage hedefi: ≥%85. CI'daki matrix Python 3.10'dan
3.13'e kadar koşturuyor.

### Lisans

MIT — bkz. [LICENSE](LICENSE).

[0rce Labs](https://github.com/orce-labs) tarafından geliştirildi.
Tasarım notları ve v0.2/v0.3 yol haritası [`docs/SPEC.md`](docs/SPEC.md)
içinde.

---


---

> **Branch koruması:** `main` branch'i kilitli. Tüm değişiklikler
> `ticket/T<N>-<slug>` formatındaki feature branch + pull request
> üzerinden geçiyor. Merge öncesi CI yeşil olmalı. Commit mesajları
> `[T<N>] <açıklama>`. Bu ayar GitHub tarafında *Settings → Branches →
> Branch protection rules* altından yapılıyor.

---

