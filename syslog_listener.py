"""
فاز ۱ — گیرنده Syslog روی TCP/UDP  (Syslog Listener)
────────────────────────────────────────────────────
تحویلیِ «دریافت Syslog از طریق TCP/UDP» در لایه ۱ سند.
سوکت واقعی باز می‌کند، خطوط خام لاگ را از شبکه می‌گیرد، آن‌ها را بافر
می‌کند و به‌صورت دسته‌ای از همان pipeline موجود (parse_logs) عبور می‌دهد،
سپس نتیجه را در لایه ذخیره‌سازی (storage.store_events) می‌نویسد.

معماری (هم‌راستا با splunk_stream.py):
    UDP/TCP socket  ─►  صف thread-safe خطوط خام
                            │  (flusher thread هر flush_interval)
                            ▼
    process_fn(content)  =  parse_logs()  →  دریافت → نرمال‌سازی ECS → dedup → غنی‌سازی
                            ▼
    store_fn(events)     =  storage.store_events()  →  ذخیره دائمی

استفاده در soc_server.py:

    from syslog_listener import start_syslog_listener, get_syslog_status
    from storage import store_events

    def _process(content):
        events, _ = parse_logs(content)
        return events

    start_syslog_listener(process_fn=_process, store_fn=store_events,
                          udp_port=5514, tcp_port=5514)

تست دستی:
    logger -n 127.0.0.1 -P 5514 -d "test message"      # UDP
    echo '<34>1 2026-... test' | nc 127.0.0.1 5514      # TCP
"""
from __future__ import annotations
import socket
import socketserver
import threading
import queue
import time
from datetime import datetime, timezone

# ── وضعیت مشترک ─────────────────────────────────────────
_line_q: "queue.Queue[str]" = queue.Queue(maxsize=50000)
_status = {
    "udp_running": False, "tcp_running": False,
    "total_received": 0, "total_stored": 0,
    "queue_size": 0, "last_error": None,
    "started_at": None,
}
_status_lock = threading.Lock()
_servers = []


def _bump(key, n=1):
    with _status_lock:
        _status[key] += n


def _enqueue(raw: bytes, peer):
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            _line_q.put_nowait(line)
            _bump("total_received")
        except queue.Full:
            with _status_lock:
                _status["last_error"] = "queue full — dropping lines"


# ── هندلرهای سوکت ───────────────────────────────────────
class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]           # UDP: (data, socket)
        _enqueue(data, self.client_address)


class _TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # syslog روی TCP معمولاً خط‌به‌خط (newline-delimited) است
        for raw in self.rfile:
            _enqueue(raw, self.client_address)


class _ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ── flusher: صف خام → pipeline → storage ────────────────
def _flusher(process_fn, store_fn, flush_interval, batch_size):
    while True:
        time.sleep(flush_interval)
        batch = []
        try:
            while len(batch) < batch_size:
                batch.append(_line_q.get_nowait())
        except queue.Empty:
            pass
        with _status_lock:
            _status["queue_size"] = _line_q.qsize()
        if not batch:
            continue
        content = "\n".join(batch)
        try:
            events = process_fn(content) or []
            if events and store_fn:
                stored = store_fn(events)
                _bump("total_stored", stored or 0)
        except Exception as e:
            with _status_lock:
                _status["last_error"] = f"process/store: {e}"


# ── راه‌اندازی ───────────────────────────────────────────
def start_syslog_listener(process_fn, store_fn=None,
                          host="0.0.0.0", udp_port=5514, tcp_port=5514,
                          flush_interval=2.0, batch_size=200,
                          enable_udp=True, enable_tcp=True):
    """
    گیرنده را در thread های پس‌زمینه راه می‌اندازد (non-blocking).
    process_fn(content:str) -> list[event dict]   (معمولاً parse_logs wrapper)
    store_fn(events) -> int                        (معمولاً storage.store_events)
    """
    with _status_lock:
        _status["started_at"] = datetime.now(timezone.utc).isoformat()

    if enable_udp:
        udp = _ThreadingUDP((host, udp_port), _UDPHandler)
        t = threading.Thread(target=udp.serve_forever, daemon=True, name="syslog-udp")
        t.start()
        _servers.append(udp)
        _status["udp_running"] = True
        print(f"📡 Syslog UDP listener → {host}:{udp_port}")

    if enable_tcp:
        tcp = _ThreadingTCP((host, tcp_port), _TCPHandler)
        t = threading.Thread(target=tcp.serve_forever, daemon=True, name="syslog-tcp")
        t.start()
        _servers.append(tcp)
        _status["tcp_running"] = True
        print(f"📡 Syslog TCP listener → {host}:{tcp_port}")

    fl = threading.Thread(target=_flusher,
                          args=(process_fn, store_fn, flush_interval, batch_size),
                          daemon=True, name="syslog-flusher")
    fl.start()
    print(f"✅ Syslog listener فعال شد (flush هر {flush_interval}s)")


def get_syslog_status() -> dict:
    with _status_lock:
        s = dict(_status)
    s["queue_size"] = _line_q.qsize()
    return s


def stop_syslog_listener():
    for srv in _servers:
        try:
            srv.shutdown()
        except Exception:
            pass
    _servers.clear()
    _status["udp_running"] = _status["tcp_running"] = False
