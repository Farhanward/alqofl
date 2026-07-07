# القفل AlQofl

القفل مكتبة وCLI لإضافة ترخيص مشفر بلا خادم لأي برنامج. الفكرة مأخوذة من نظام GrowBox القديم، لكن هذه النسخة تفصل مفاتيح الإصدار عن التحقق، وتولد المفاتيح محلياً بدلاً من seed تطويري ثابت.

## آلية العمل

1. `keygen` يولد زوج مفاتيح Ed25519.
2. `fingerprint` يحول أجزاء الجهاز إلى hash خاص.
3. `issue` يصدر كود `ALQ-...` يحتوي claims موقعة.
4. `verify` يتحقق محلياً من التوقيع، التطبيق، الجهاز، والانتهاء.
5. `activate/status` يحفظ الترخيص محلياً ويكشف rollback الساعة.
6. `proof` ينتج إثبات استخدام يومي لا يكشف الإيميل أو رقم الجهاز الخام.

## تشغيل سريع

```powershell
python -m alqofl.cli keygen
$device = python -m alqofl.cli fingerprint cpu-demo disk-demo machine-demo
$code = python -m alqofl.cli issue --app-id app.demo --customer user@example.com --device-hash $device --feature pro --days 30
python -m alqofl.cli verify --code $code --app-id app.demo --device-hash $device
```

## اختبار كبير

```powershell
python -m alqofl.cli benchmark --input C:\Projects\kashif\data\external\nvd_cves_12000.jsonl
```

يستخدم بيانات NVD التي جلبها مشروع كاشف من الإنترنت بعدد 12,000 سجل.

## آخر نتائج

- الاختبارات الذاتية: 6/6 ناجحة.
- Ledger: verified، 21 سجل.
- Benchmark NVD: 12,000 رخصة صحيحة، 12,000 تحقق ناجح، 0 فشل.
- Tamper tests: 705 محاولة تلاعب، 705 مكتشفة.
- الأداء: p99=1.01ms، peak memory=0.43MB، elapsed=10.54s.

## تحسينات إنتاجية 2026-07-04

- `issue_license()` يرفض الآن أي مدة ترخيص غير موجبة بدلاً من تحويلها صامتاً إلى يوم واحد.
- `verify_license()` يوحد تواريخ الرخصة إلى UTC، ويرفض الرخص الصادرة في المستقبل أو ذات انتهاء غير صالح قبل حساب الأيام المتبقية.
- `activate()` ينشئ مجلدات مسار ملف التفعيل والساعة قبل الكتابة، لذلك يعمل مع مسارات حالة متداخلة داخل تطبيقات حقيقية.

## التشغيل المؤسسي (Enterprise) — v1.0.0

- **خدمة تحقق مركزية**: `python -m alqofl.cli serve` → `POST /api/verify {"code","app_id","device_hash"}`.
- **قرار أمني**: الإصدار (`issue`) عبر CLI فقط — الخدمة الشبكية لا تلمس المفتاح الخاص إطلاقاً (`ALQOFL_PUBLIC_KEY` فقط).
- **نقاط فحص**: `/api/health` (مفتوح) · `/api/version` · `/api/metrics`.
- **تهيئة عبر البيئة**: متغيرات `ALQOFL_*` — انظر `docs/OPERATIONS.md`.
- **مصادقة**: `ALQOFL_API_KEY` → ترويسة `X-API-Key`. **سجلات JSON**: `logs\alqofl.service.jsonl`.
