# فاز ۲ — پایگاه دانش امنیتی آفلاین

این بسته چهار جزء مستقل و محلی دارد:

1. **MITRE RAG** با ChromaDB و مدل `nomic-embed-text`
2. **MITRE Graph** با ساختار Tactic → Technique → Sub-technique
3. **CVE Store** محلی با SQLite و ورودی استاندارد NVD JSON 2.0
4. **Incident Memory** برای ذخیره و بازیابی معنایی رخدادهای تاریخی

هیچ داده‌ای به سرویس ابری ارسال نمی‌شود. تنها وابستگی زمان اجرا Ollama محلی است.

## نصب

```bash
python3 -m venv ai-venv
source ai-venv/bin/activate
pip install -r requirements.txt
ollama pull nomic-embed-text
```

## ساخت اولیه

```bash
python3 build_mitre_rag.py --rebuild
python3 phase2_cli.py build-graph
python3 phase2_cli.py status
```

## جست‌وجوی MITRE و گراف

```bash
python3 phase2_cli.py search-mitre "multiple failed login attempts brute force"
python3 phase2_cli.py graph-query T1001 --depth 2
```

در `soc_server.py` می‌توان مستقیماً استفاده کرد:

```python
from mitre_search import search_mitre, format_mitre_context

mitre_results = search_mitre(alert_text, n_results=3, min_similarity=0.60)
prompt_context = format_mitre_context(mitre_results)
```

## CVE آفلاین

فایل رسمی NVD با قالب JSON 2.0 را در شبکه مجاز سازمان دریافت و سپس وارد کنید:

```bash
python3 phase2_cli.py import-cve /path/to/nvdcve-feed.json
python3 phase2_cli.py search-cve nginx --min-cvss 7
```

برای تطبیق درست CVE، فیلدهای `products` یا `cpe` هر دارایی در `assets.json` باید واقعی باشند.

## حافظه رخداد

```bash
python3 phase2_cli.py add-incident sample_incident.json
python3 phase2_cli.py search-incidents "SSH brute force from external host"
```

## تست و پذیرش

```bash
python3 -m unittest -v test_phase2.py
python3 acceptance_phase2.py
```

تست پذیرش چهار Query استاندارد را بررسی می‌کند؛ تکنیک مورد انتظار باید در پنج نتیجه اول و
Similarity آن حداقل ۶۰٪ باشد. همچنین وجود مسیر چندمرحله‌ای در Graph بررسی می‌شود.

## نکات عملیاتی

- مسیرهای پیش‌فرض زیر پوشه `data/` هستند و باید در Backup لحاظ شوند.
- اجرای دوباره `build_mitre_rag.py` از `upsert` استفاده می‌کند و داده تکراری نمی‌سازد.
- برای بازسازی کامل ایندکس از `--rebuild` استفاده کنید.
- فایل `.env.example` فقط الگو است؛ مقادیر واقعی را در `.env` قرار دهید.
