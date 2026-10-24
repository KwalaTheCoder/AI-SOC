# چک‌لیست تحویل فاز ۲

- [x] Parse و Dataset محلی MITRE ATT&CK (۶۹۷ Technique/Sub-technique)
- [x] Embedding محلی و Batch با Ollama
- [x] Vector Store پایدار و Idempotent در ChromaDB
- [x] Semantic Search و خروجی Similarity
- [x] Knowledge Graph مبتنی بر NetworkX
- [x] Query چندمرحله‌ای Graph
- [x] SQLite CVE Store
- [x] Importer استاندارد NVD JSON 2.0
- [x] Asset-to-CVE Risk Scoring
- [x] Incident Vector Memory
- [x] CLI عملیاتی یکپارچه
- [x] Unit Test آفلاین
- [ ] اجرای Acceptance با Ollama روی سرور نهایی و ثبت خروجی ۴ Query
- [ ] ورود Feed واقعی NVD سازمان و جایگزینی مشخصات نمونه Assetها

دو مورد آخر «استقرار و داده محیط مشتری» هستند و به کدنویسی وابسته نیستند؛ برای صورت‌جلسه
تحویل، خروجی دستورهای زیر ضمیمه شود:

```bash
python3 acceptance_phase2.py | tee phase2_acceptance_result.json
python3 phase2_cli.py status | tee phase2_status.json
```
