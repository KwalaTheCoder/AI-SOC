"""
فاز ۱ — اتصال زنده به Splunk (جایگزین آپلود دستی فایل)
این ماژول read_splunks_logs.py رو به‌عنوان کتابخونه import می‌کنه (نه subprocess)
و event ها رو مستقیم توی همون pipeline پارس/غنی‌سازی موجود در soc_server.py می‌ریزه.

معماری:
    Splunk REST API (splunklib)
        ↓ stream_events() [historical backfill + live poll]
    یه Thread پس‌زمینه جدا
        ↓ merge_event() → dict خام Splunk (شامل _raw)
    _splunk_dict_to_line() → تبدیل به همون فرمتی که parse_splunk_suricata می‌فهمه
        ↓
    parse_splunk_suricata() [از soc_server.py — بدون تغییر]
        ↓
    LIVE_EVENTS buffer (thread-safe, رینگ بافر با سقف حجم)
        ↓
    /live-status و /analyze-live در soc_server.py ازش می‌خونن

استفاده در soc_server.py:

    from splunk_stream import start_splunk_stream, get_live_events, get_stream_status

    start_splunk_stream(parse_fn=parse_splunk_suricata, enrich_fn=enrich_pipeline)
"""

import os
import json
import threading
import time
from collections import deque
from datetime import datetime

# splunklib عمداً این‌جا import نمی‌شه (lazy import داخل _connect).
# دلیل: این یه وابستگی اختیاریه فقط برای stream زنده. اگه بالای فایل import
# می‌شد و روی سیستم کاربر نصب نبود، کل soc_server.py موقع استارت کرش می‌کرد —
# حتی برای کسی که اصلاً از Splunk استفاده نمی‌کنه و فقط می‌خواد فایل آپلود کنه.

# ── تنظیمات (از environment یا مقدار پیش‌فرض) ──────────────
SPLUNK_HOST          = os.environ.get("SPLUNK_HOST", "127.0.0.1")
SPLUNK_PORT          = int(os.environ.get("SPLUNK_PORT", "8089"))
SPLUNK_INDEX         = os.environ.get("SPLUNK_INDEX", "suricata")
SPLUNK_SOURCETYPE    = os.environ.get("SPLUNK_SOURCETYPE", "suricata:eve:json")
SPLUNK_LOOKBACK      = os.environ.get("SPLUNK_LOOKBACK", "-15m")
SPLUNK_POLL_SECONDS  = float(os.environ.get("SPLUNK_POLL_SECONDS", "2"))

MAX_BUFFER_SIZE = 20000   # سقف رینگ‌بافر — از این بیشتر بشه قدیمی‌ترین‌ها حذف میشن

# ── State مشترک بین Thread ها ──────────────────────────────
LIVE_EVENTS   = deque(maxlen=MAX_BUFFER_SIZE)   # رویدادهای پارس‌شده و enrich‌شده
_buffer_lock  = threading.Lock()

_stream_state = {
    "connected":      False,
    "running":        False,
    "total_received": 0,
    "total_parsed":   0,
    "last_event_at":  None,
    "last_error":     None,
    "started_at":     None,
}
_state_lock = threading.Lock()


def _update_state(**kwargs):
    with _state_lock:
        _stream_state.update(kwargs)


def get_stream_status():
    with _state_lock:
        return dict(_stream_state)


def get_live_events(clear=False, limit=None):
    """
    خواندن رویدادهای موجود در بافر.
    clear=True → بافر رو خالی می‌کنه بعد از خوندن (برای /analyze-live که فقط رویدادهای جدید رو می‌خواد)
    limit       → فقط N تای آخر رو برگردون
    """
    with _buffer_lock:
        items = list(LIVE_EVENTS)
        if clear:
            LIVE_EVENTS.clear()
    if limit:
        items = items[-limit:]
    return items


def push_live_events(events):
    """
    اضافه کردن رویدادهای از‌قبل پارس/ECS-enrich‌شده به همون بافر زنده‌ای
    که /analyze-live می‌خونه. با این تابع، منابع دیگه (Syslog listener،
    NetFlow collector) هم می‌تونن وارد چرخه تحلیل هوش مصنوعی بشن — نه
    فقط Splunk. thread-safe (همون _buffer_lock رو استفاده می‌کنه).
    خروجی: تعداد رویدادی که واقعاً اضافه شد.
    """
    if not events:
        return 0
    with _buffer_lock:
        for e in events:
            LIVE_EVENTS.append(e)
    return len(events)


# ── اتصال به Splunk ─────────────────────────────────────────
def _connect():
    try:
        import splunklib.client as client
    except ImportError:
        raise RuntimeError(
            "کتابخونه splunklib نصب نیست. برای استفاده از اتصال زنده به Splunk اجرا کن:\n"
            "  pip install splunk-sdk --break-system-packages\n"
            "(بدون این کتابخونه، بقیه سرور — آپلود فایل، داشبورد، Syslog، NetFlow — عادی کار می‌کنه.)"
        )

    username = os.environ.get("SPLUNK_USERNAME")
    password = os.environ.get("SPLUNK_PASSWORD")
    token    = os.environ.get("SPLUNK_SESSION_TOKEN")

    if not token and not (username and password):
        raise RuntimeError(
            "اطلاعات ورود Splunk تنظیم نشده. یکی از این‌ها رو ست کن:\n"
            "  SPLUNK_USERNAME + SPLUNK_PASSWORD\n"
            "  یا SPLUNK_SESSION_TOKEN"
        )

    kwargs = {"host": SPLUNK_HOST, "port": SPLUNK_PORT}
    if token:
        kwargs["splunkToken"] = token
    else:
        kwargs["username"] = username
        kwargs["password"] = password

    return client.connect(**kwargs)


def _merge_event(event):
    """همون merge_event اصلی از read_splunks_logs.py"""
    raw = event.get("_raw", "")
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {"_raw": raw}
    parsed.update(event)
    return parsed


def _splunk_dict_to_splunk_line(merged_event):
    """
    parse_splunk_suricata توی soc_server.py انتظار یه *رشته* JSON با ساختار
    {"result": {"_raw": "...", "host": "..."}} رو داره (خروجی search API کلاسیک Splunk).
    این تابع dict merge‌شده رو دوباره به همون ساختار برمی‌گردونه تا parser بدون تغییر کار کنه.
    """
    raw_json = merged_event.get("_raw", "")
    if not raw_json:
        # اگه _raw نبود، خود merged_event رو serialize کن
        raw_json = json.dumps({k: v for k, v in merged_event.items() if not k.startswith('_')})

    wrapper = {
        "result": {
            "_raw":  raw_json,
            "host":  merged_event.get("host", ""),
            "_time": merged_event.get("_time", ""),
            "index": merged_event.get("index", ""),
        }
    }
    return json.dumps(wrapper)


SPLUNK_QUERIES = [
    f"search index={SPLUNK_INDEX} sourcetype={SPLUNK_SOURCETYPE} "
    f"| spath | search event_type=alert ",
]

_RECONNECT_DELAY   = 10   # ثانیه انتظار قبل از reconnect
_MAX_RECONNECTS    = 0    # 0 = بی‌نهایت


def _stream_events_generator(service, lookback, poll_seconds):
    """
    چند query موازی — هر query یه ژنراتور مستقل
    backfill یک‌بار، بعد live poll برای همه
    """
    import splunklib.results as results

    def fetch(query, earliest):
        for attempt in (1, 2):
            try:
                stream = service.jobs.export(
                    query, output_mode="json",
                    earliest_time=earliest, latest_time="now",
                )
                return [e for e in results.JSONResultsReader(stream) if isinstance(e, dict)]
            except Exception as exc:
                if attempt == 2:
                    _update_state(last_error=f"[{query[:40]}] search failed: {exc}")
                    return []
                time.sleep(1)

    # وضعیت هر query: {query: (last_indextime, seen_ids)}
    q_state = {q: (0, set()) for q in SPLUNK_QUERIES}

    # Phase 1: backfill همه query ها
    for q in SPLUNK_QUERIES:
        last_t, seen = q_state[q]
        for event in fetch(q, lookback):
            yield _merge_event(event)
            t = int(event.get("_indextime", 0))
            cd = event.get("_cd")
            if t > last_t:
                last_t, seen = t, {cd}
            elif t == last_t:
                seen.add(cd)
        q_state[q] = (last_t, seen)

    # Phase 2: live poll همه query ها
    while True:
        time.sleep(poll_seconds)
        for q in SPLUNK_QUERIES:
            last_t, seen = q_state[q]
            for event in fetch(q, last_t or lookback):
                cd = event.get("_cd")
                t  = int(event.get("_indextime", 0))
                if t < last_t:
                    continue
                if t == last_t and cd in seen:
                    continue
                yield _merge_event(event)
                if t > last_t:
                    last_t, seen = t, {cd}
                else:
                    seen.add(cd)
            q_state[q] = (last_t, seen)


def _run_stream_loop(parse_fn, store_fn=None):
    """
    حلقه اصلی با reconnect خودکار.
    اگه Splunk کانکشن رو ببنده یا هر خطایی بده، بعد از RECONNECT_DELAY دوباره وصل میشه.
    """
    reconnect_count = 0

    while _MAX_RECONNECTS == 0 or reconnect_count <= _MAX_RECONNECTS:
        _update_state(
            started_at=datetime.utcnow().isoformat(),
            running=True, last_error=None, connected=False
        )

        try:
            service = _connect()
            _update_state(connected=True)
            print(f"✅ Splunk connected: {SPLUNK_HOST}:{SPLUNK_PORT} "
                  f"(index={SPLUNK_INDEX}, {len(SPLUNK_QUERIES)} queries)")
        except Exception as e:
            _update_state(connected=False, running=False, last_error=str(e))
            print(f"❌ Splunk connection failed: {e}")
            print(f"   ⏳ reconnect در {_RECONNECT_DELAY}s ...")
            time.sleep(_RECONNECT_DELAY)
            reconnect_count += 1
            continue

        try:
            for merged in _stream_events_generator(service, SPLUNK_LOOKBACK, SPLUNK_POLL_SECONDS):
                _update_state(
                    total_received=_stream_state["total_received"] + 1,
                    last_event_at=datetime.utcnow().isoformat()
                )
                line   = _splunk_dict_to_splunk_line(merged)
                parsed = parse_fn(line)
                if parsed:
                    with _buffer_lock:
                        LIVE_EVENTS.append(parsed)
                    _update_state(total_parsed=_stream_state["total_parsed"] + 1)
                    if store_fn:
                        try:
                            store_fn([parsed])
                        except Exception as se:
                            _update_state(last_error=f"store: {se}")

        except Exception as e:
            err = str(e)
            _update_state(running=False, connected=False, last_error=err)
            print(f"❌ Splunk stream error: {err}")
            print(f"   ⏳ reconnect در {_RECONNECT_DELAY}s ... (تلاش {reconnect_count + 1})")
            time.sleep(_RECONNECT_DELAY)
            reconnect_count += 1


def start_splunk_stream(parse_fn, store_fn=None):
    """
    شروع stream زنده در یه daemon thread جدا.
    reconnect خودکار در صورت قطع کانکشن — بی‌نهایت تلاش.
    parse_fn = parse_splunk_suricata از soc_server.py
    store_fn = storage.store_events (اختیاری)
    """
    t = threading.Thread(target=_run_stream_loop, args=(parse_fn, store_fn), daemon=True)
    t.start()
    return t


# ── تست مستقل ────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    def _dummy_parser(line):
        """برای تست بدون وابستگی به soc_server.py"""
        try:
            outer = json.loads(line)
            raw = outer.get('result', {}).get('_raw', '')
            inner = json.loads(raw) if raw else {}
            return {"event_type": inner.get("event_type"), "src_ip": inner.get("src_ip")}
        except:
            return None

    print(f"[*] Testing Splunk stream: {SPLUNK_HOST}:{SPLUNK_PORT}/{SPLUNK_INDEX}")
    start_splunk_stream(parse_fn=_dummy_parser)

    try:
        while True:
            time.sleep(3)
            status = get_stream_status()
            events = get_live_events()
            print(f"[status] connected={status['connected']} received={status['total_received']} "
                  f"parsed={status['total_parsed']} buffer={len(events)} error={status['last_error']}")
    except KeyboardInterrupt:
        sys.exit(0)
