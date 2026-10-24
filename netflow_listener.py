"""
فاز ۱ — گیرنده NetFlow v5/v9 / IPFIX / sFlow  (Flow Collector)
─────────────────────────────────────────────────────────────
تحویلیِ «تحلیل جریان شبکه (NetFlow/sFlow/PCAP)» در لایه ۱ سند.

این نسخه سه پروتکل باینری متفاوت رو decode می‌کنه:
  • NetFlow v5   — فرمت ثابت (fixed-format)، رکوردها همیشه ۴۸ بایت
  • NetFlow v9 / IPFIX (v10) — پروتکل template-محور: قبل از هر Data Set
    باید یه Template Set دیده شده باشه که میگه هر فیلد چند بایته و چیه
  • sFlow v5     — کاملاً فرمت متفاوت: هر Sample شامل هدر خام یه بسته
    اترنت/IP واقعیه که باید جدا decode بشه (نه فرمت شمارشی مثل NetFlow)

نکته فنی مهم: بایت‌های اول NetFlow v5 (2 بایت version + 2 بایت count)
می‌تونه با بایت‌های اول sFlow v5 (4 بایت version) قاطی بشه چون هر دو
version=5 هستن. برای رفع ابهام، sFlow رو روی یه پورت جدا (۶۳۴۳،
استاندارد صنعتی) گوش می‌دیم — نه با حدس‌زدن از روی بایت‌ها.

معماری:
    UDP:2055 (NetFlow v5/v9/IPFIX) ──┐
                                      ├─► decode_*() ─► event dict ─► process_fn ─► store_fn
    UDP:6343 (sFlow)         ────────┘

استفاده در soc_server.py: بدون تغییر — همون start_netflow_listener()
"""
from __future__ import annotations
import socket
import socketserver
import struct
import threading
import queue
import time
from datetime import datetime, timezone

# ── نگاشت شماره پروتکل IP → نام ─────────────────────────
_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "ipv6-icmp"}

# ── وضعیت مشترک ─────────────────────────────────────────
_pkt_q: "queue.Queue[tuple[bytes, tuple]]" = queue.Queue(maxsize=20000)
_sflow_q: "queue.Queue[tuple[bytes, tuple]]" = queue.Queue(maxsize=20000)

_status = {
    "running": False, "port": None,
    "sflow_running": False, "sflow_port": None,
    "packets_received": 0, "flows_decoded": 0, "flows_stored": 0,
    "sflow_packets_received": 0, "sflow_flows_decoded": 0,
    "unsupported_versions": {}, "last_error": None, "started_at": None,
    "templates_known": 0,
}
_status_lock = threading.Lock()
_servers = []


def _bump(key, n=1):
    with _status_lock:
        _status[key] += n


# ══════════════════════════════════════════════════════════════
# NetFlow v5 — فرمت ثابت (بدون تغییر نسبت به قبل)
# ══════════════════════════════════════════════════════════════
_V5_HEADER = struct.Struct("!HHIIIIBBH")   # 24 bytes
_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")  # 48 bytes


def decode_netflow_v5(data: bytes, unix_secs: int | None = None) -> list[dict]:
    """یک بسته NetFlow v5 را به لیست event dict تبدیل می‌کند."""
    if len(data) < _V5_HEADER.size:
        return []
    (version, count, sys_uptime, secs, nsecs,
     flow_seq, eng_type, eng_id, sampling) = _V5_HEADER.unpack_from(data, 0)
    if version != 5:
        return []
    ts = datetime.fromtimestamp(secs or (unix_secs or time.time()), timezone.utc).isoformat()

    events = []
    offset = _V5_HEADER.size
    for _ in range(min(count, (len(data) - offset) // _V5_RECORD.size)):
        r = _V5_RECORD.unpack_from(data, offset)
        offset += _V5_RECORD.size
        (srcaddr, dstaddr, nexthop, inp, outp, dpkts, doctets,
         first, last, srcport, dstport, pad1, tcp_flags, prot, tos,
         src_as, dst_as, src_mask, dst_mask, pad2) = r
        proto = _PROTO.get(prot, str(prot))
        events.append({
            "timestamp":   ts,
            "severity":    "INFO",
            "event_type":  "netflow",
            "category":    "flow",
            "action":      "NETWORK_FLOW",
            "src_ip":      _ip(srcaddr),
            "dest_ip":     _ip(dstaddr),
            "src_port":    srcport,
            "dest_port":   dstport,
            "proto":       proto,
            "bytes":       doctets,
            "packets":     dpkts,
            "tcp_flags":   tcp_flags,
            "signature":   f"flow {proto} {_ip(srcaddr)}:{srcport} -> {_ip(dstaddr)}:{dstport} ({doctets}B)",
            "host":        "",
        })
    return events


def _ip(addr_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", addr_int))


# ══════════════════════════════════════════════════════════════
# NetFlow v9 / IPFIX (v10) — پروتکل template-محور
# ══════════════════════════════════════════════════════════════
_V9_HEADER    = struct.Struct("!HHIIII")   # version,count,sysUptime,unixSecs,seq,sourceId (20B)
_IPFIX_HEADER = struct.Struct("!HHIII")    # version,length,exportTime,seq,domainId        (16B)

# نگاشت فیلدهای استاندارد NetFlow v9 / IPFIX Information Elements (زیرمجموعه‌ی پراستفاده)
_FT_IN_BYTES, _FT_IN_PKTS   = 1, 2
_FT_PROTOCOL                = 4
_FT_L4_SRC_PORT             = 7
_FT_IPV4_SRC_ADDR           = 8
_FT_L4_DST_PORT             = 11
_FT_IPV4_DST_ADDR           = 12
_FT_IPV6_SRC_ADDR           = 27
_FT_IPV6_DST_ADDR           = 28

# (exporter_ip, template_id) → [(field_type, field_len), ...]
_TEMPLATES: dict[tuple, list[tuple[int, int]]] = {}


def _parse_template_set(data: bytes, pos: int, end: int, exporter_ip: str, is_ipfix: bool) -> None:
    """پارس یک Template Set/FlowSet — می‌تونه چند Template Record پشت‌سرهم داشته باشه."""
    while pos + 4 <= end:
        template_id, field_count = struct.unpack_from("!HH", data, pos)
        pos += 4
        if template_id < 256 or field_count == 0 or field_count > 128:
            break  # مقدار نامعتبر → از ادامه پارس این Set صرف‌نظر کن (امن، بدون crash)
        fields = []
        ok = True
        for _ in range(field_count):
            if pos + 4 > end:
                ok = False
                break
            ftype, flen = struct.unpack_from("!HH", data, pos)
            pos += 4
            if is_ipfix and (ftype & 0x8000):
                # فیلد enterprise-specific (IPFIX RFC7011) — ۴ بایت Enterprise Number اضافه داره
                if pos + 4 > end:
                    ok = False
                    break
                pos += 4
                ftype &= 0x7FFF
            fields.append((ftype, flen))
        if ok:
            _TEMPLATES[(exporter_ip, template_id)] = fields
        with _status_lock:
            _status["templates_known"] = len(_TEMPLATES)


def _field_to_ip(raw: bytes) -> str:
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    if len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def _field_to_int(raw: bytes) -> int:
    return int.from_bytes(raw, "big") if raw else 0


def _record_to_event(rec: dict, ts: str) -> dict:
    src_ip = _field_to_ip(rec.get(_FT_IPV4_SRC_ADDR, b"")) or _field_to_ip(rec.get(_FT_IPV6_SRC_ADDR, b""))
    dst_ip = _field_to_ip(rec.get(_FT_IPV4_DST_ADDR, b"")) or _field_to_ip(rec.get(_FT_IPV6_DST_ADDR, b""))
    src_port = _field_to_int(rec.get(_FT_L4_SRC_PORT, b""))
    dst_port = _field_to_int(rec.get(_FT_L4_DST_PORT, b""))
    proto_num = _field_to_int(rec.get(_FT_PROTOCOL, b""))
    proto = _PROTO.get(proto_num, str(proto_num) if proto_num else "")
    in_bytes = _field_to_int(rec.get(_FT_IN_BYTES, b""))
    in_pkts  = _field_to_int(rec.get(_FT_IN_PKTS, b""))
    return {
        "timestamp": ts, "severity": "INFO", "event_type": "netflow",
        "category": "flow", "action": "NETWORK_FLOW",
        "src_ip": src_ip, "dest_ip": dst_ip,
        "src_port": src_port, "dest_port": dst_port,
        "proto": proto, "bytes": in_bytes, "packets": in_pkts,
        "signature": f"flow {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({in_bytes}B)",
        "host": "",
    }


def _parse_data_set(data: bytes, pos: int, end: int, exporter_ip: str,
                    template_id: int, ts: str) -> list[dict]:
    fields = _TEMPLATES.get((exporter_ip, template_id))
    if not fields:
        return []  # هنوز Template این ID رو ندیدیم — این Data Set قابل decode نیست (طبیعیه، معمولاً چند بسته بعد میاد)
    record_len = sum(fl for _, fl in fields)
    if record_len <= 0:
        return []
    events = []
    while pos + record_len <= end:
        rec = {}
        p = pos
        for ftype, flen in fields:
            rec[ftype] = data[p:p+flen]
            p += flen
        pos += record_len
        events.append(_record_to_event(rec, ts))
    return events


def decode_netflow_v9_or_ipfix(data: bytes, exporter_ip: str) -> list[dict]:
    """پارس یک بسته NetFlow v9 یا IPFIX (v10)، با نگهداری template cache."""
    if len(data) < 4:
        return []
    version = struct.unpack_from("!H", data, 0)[0]

    if version == 9:
        if len(data) < _V9_HEADER.size:
            return []
        _, _count, _uptime, unix_secs, _seq, _src_id = _V9_HEADER.unpack_from(data, 0)
        ts = datetime.fromtimestamp(unix_secs or time.time(), timezone.utc).isoformat()
        offset, end, is_ipfix = _V9_HEADER.size, len(data), False
        TEMPLATE_ID, OPTS_TEMPLATE_ID = 0, 1
    elif version == 10:
        if len(data) < _IPFIX_HEADER.size:
            return []
        _, length, export_time, _seq, _domain = _IPFIX_HEADER.unpack_from(data, 0)
        ts = datetime.fromtimestamp(export_time or time.time(), timezone.utc).isoformat()
        offset, is_ipfix = _IPFIX_HEADER.size, True
        end = min(length, len(data)) if length else len(data)
        TEMPLATE_ID, OPTS_TEMPLATE_ID = 2, 3
    else:
        return []

    events = []
    while offset + 4 <= end:
        set_id, set_len = struct.unpack_from("!HH", data, offset)
        if set_len < 4 or offset + set_len > end:
            break  # طول نامعتبر → از ادامه صرف‌نظر کن (امن)
        content_start, content_end = offset + 4, offset + set_len

        if set_id == TEMPLATE_ID:
            _parse_template_set(data, content_start, content_end, exporter_ip, is_ipfix)
        elif set_id == OPTS_TEMPLATE_ID:
            pass  # Options Template — فرمت Scope+Option متفاوته، فعلاً پشتیبانی نمی‌شه (skip امن)
        elif set_id >= 256:
            events.extend(_parse_data_set(data, content_start, content_end, exporter_ip, set_id, ts))
        offset += set_len
    return events


# ══════════════════════════════════════════════════════════════
# دیکدر مشترک بسته خام Ethernet/IPv4 — هم برای sFlow هم برای PCAP
# ══════════════════════════════════════════════════════════════
def decode_ethernet_ipv4_packet(raw: bytes) -> dict | None:
    """
    یک فریم Ethernet خام رو به {src_ip, dest_ip, src_port, dest_port, proto} تبدیل می‌کنه.
    فقط Ethernet II + IPv4 (با/بدون VLAN tag 802.1Q) رو پشتیبانی می‌کنه.
    IPv6 و فریم‌های غیر-IP فعلاً پشتیبانی نمی‌شن (None برمی‌گردونه، بدون خطا).
    """
    if len(raw) < 14:
        return None
    eth_type = struct.unpack_from("!H", raw, 12)[0]
    offset = 14
    if eth_type == 0x8100:  # VLAN tag (802.1Q)
        if len(raw) < offset + 4:
            return None
        eth_type = struct.unpack_from("!H", raw, offset + 2)[0]
        offset += 4

    if eth_type != 0x0800:   # فقط IPv4 (0x0800)
        return None
    if len(raw) < offset + 20:
        return None

    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl:
        return None
    proto_num = raw[offset + 9]
    src_ip = socket.inet_ntoa(raw[offset+12:offset+16])
    dst_ip = socket.inet_ntoa(raw[offset+16:offset+20])
    l4_offset = offset + ihl

    src_port = dst_port = 0
    if proto_num in (6, 17) and len(raw) >= l4_offset + 4:  # TCP یا UDP
        src_port, dst_port = struct.unpack_from("!HH", raw, l4_offset)

    return {
        "src_ip": src_ip, "dest_ip": dst_ip,
        "src_port": src_port, "dest_port": dst_port,
        "proto": _PROTO.get(proto_num, str(proto_num)),
    }


# ══════════════════════════════════════════════════════════════
# sFlow v5 — فرمت کاملاً متفاوت (raw packet sampling، نه template)
# ══════════════════════════════════════════════════════════════
def decode_sflow_v5(data: bytes) -> list[dict]:
    """
    پارس یک بسته sFlow v5. فقط Flow Sample (format=1) و Expanded Flow
    Sample (format=3) با رکورد Raw Packet Header (format=1) رو decode
    می‌کنه — یعنی همون چیزی که برای تشخیص تهدید امنیتی لازمه.
    Counter Sample (format=2/4، آمار رابط شبکه) نادیده گرفته می‌شه.
    """
    if len(data) < 8:
        return []
    version, addr_type = struct.unpack_from("!II", data, 0)
    if version != 5:
        return []
    offset = 8
    addr_len = {1: 4, 2: 16}.get(addr_type, 0)
    if addr_len == 0 or len(data) < offset + addr_len + 16:
        return []
    offset += addr_len  # agent address رو رد کن
    _sub_agent, _seq, _uptime, num_samples = struct.unpack_from("!IIII", data, offset)
    offset += 16
    ts = datetime.now(timezone.utc).isoformat()

    events = []
    for _ in range(min(num_samples, 10000)):  # سقف امنیتی در برابر بسته خراب/مخرب
        if offset + 8 > len(data):
            break
        sample_type, sample_len = struct.unpack_from("!II", data, offset)
        sample_start = offset + 8
        sample_end   = sample_start + sample_len
        if sample_len == 0 or sample_end > len(data):
            break
        fmt = sample_type & 0xFFF
        if fmt in (1, 3):
            events.extend(_parse_sflow_flow_sample(data, sample_start, sample_end, fmt, ts))
        offset = sample_end
    return events


def _parse_sflow_flow_sample(data: bytes, start: int, end: int, fmt: int, ts: str) -> list[dict]:
    events = []
    try:
        if fmt == 1:
            if start + 32 > end:
                return []
            num_records = struct.unpack_from("!I", data, start + 28)[0]
            pos = start + 32
        else:  # Expanded Flow Sample
            if start + 36 > end:
                return []
            num_records = struct.unpack_from("!I", data, start + 32)[0]
            pos = start + 36

        for _ in range(min(num_records, 1000)):
            if pos + 8 > end:
                break
            flow_format, flow_len = struct.unpack_from("!II", data, pos)
            rec_start, rec_end = pos + 8, pos + 8 + flow_len
            if flow_len == 0 or rec_end > end:
                break
            if (flow_format & 0xFFF) == 1:  # Raw Packet Header
                ev = _parse_sflow_raw_packet(data, rec_start, rec_end, ts)
                if ev:
                    events.append(ev)
            pad = (-flow_len) % 4  # رکوردهای sFlow به مضرب ۴ بایت pad می‌شن
            pos = rec_end + pad
    except (struct.error, IndexError):
        pass
    return events


def _parse_sflow_raw_packet(data: bytes, start: int, end: int, ts: str) -> dict | None:
    if start + 16 > end:
        return None
    header_protocol, frame_length, _stripped, header_length = struct.unpack_from("!IIII", data, start)
    if header_protocol != 1:  # فقط Ethernet (سایر مقادیر: FDDI/TokenRing/... پشتیبانی نمی‌شه)
        return None
    hdr_start = start + 16
    hdr_end   = min(hdr_start + header_length, end)
    parsed = decode_ethernet_ipv4_packet(data[hdr_start:hdr_end])
    if not parsed:
        return None
    return {
        "timestamp": ts, "severity": "INFO", "event_type": "sflow",
        "category": "flow", "action": "NETWORK_FLOW",
        "src_ip": parsed["src_ip"], "dest_ip": parsed["dest_ip"],
        "src_port": parsed["src_port"], "dest_port": parsed["dest_port"],
        "proto": parsed["proto"], "bytes": frame_length, "packets": 1,
        "signature": f"sflow {parsed['proto']} {parsed['src_ip']}:{parsed['src_port']} -> "
                     f"{parsed['dest_ip']}:{parsed['dest_port']}",
        "host": "",
    }


# ══════════════════════════════════════════════════════════════
# PCAP فایل — پارس فایل آپلودشده (نه listener زنده؛ استفاده در /analyze)
# ══════════════════════════════════════════════════════════════
_PCAP_MAGIC_LE = 0xa1b2c3d4
_PCAP_MAGIC_BE = 0xd4c3b2a1
_PCAP_MAGIC_LE_NS = 0xa1b23c4d   # nanosecond-resolution variant
_PCAP_MAGIC_BE_NS = 0x4d3cb2a1


def is_pcap_file(data: bytes) -> bool:
    """تشخیص فایل PCAP کلاسیک از روی magic number (۴ بایت اول)."""
    if len(data) < 4:
        return False
    magic = struct.unpack_from("<I", data, 0)[0]
    return magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAP_MAGIC_LE_NS, _PCAP_MAGIC_BE_NS)


def decode_pcap_file(data: bytes) -> list[dict]:
    """
    پارس یک فایل PCAP کلاسیک (libpcap format) — نه pcapng (که فرمت جدیدتر
    و متفاوتیه و فعلاً پشتیبانی نمی‌شه).
    فقط لینک‌لایه Ethernet (LINKTYPE_ETHERNET=1) رو پشتیبانی می‌کنه.
    """
    if len(data) < 24:
        return []
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_LE_NS):
        endian = "<"
    elif magic in (_PCAP_MAGIC_BE, _PCAP_MAGIC_BE_NS):
        endian = ">"
    else:
        return []  # فایل PCAP معتبر نیست (یا pcapng هست که پشتیبانی نمی‌شه)

    ver_major, ver_minor, thiszone, sigfigs, snaplen, network = \
        struct.unpack_from(f"{endian}HHiIII", data, 4)
    if network != 1:  # فقط LINKTYPE_ETHERNET
        return []

    events = []
    offset = 24
    rec_hdr = struct.Struct(f"{endian}IIII")  # ts_sec, ts_usec, incl_len, orig_len
    while offset + rec_hdr.size <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = rec_hdr.unpack_from(data, offset)
        offset += rec_hdr.size
        if offset + incl_len > len(data):
            break  # فایل ناقص/بریده‌شده — امن متوقف شو
        packet_bytes = data[offset:offset + incl_len]
        offset += incl_len

        parsed = decode_ethernet_ipv4_packet(packet_bytes)
        if parsed:
            ts = datetime.fromtimestamp(ts_sec, timezone.utc).isoformat()
            events.append({
                "timestamp": ts, "severity": "INFO", "event_type": "pcap",
                "category": "flow", "action": "NETWORK_FLOW",
                "src_ip": parsed["src_ip"], "dest_ip": parsed["dest_ip"],
                "src_port": parsed["src_port"], "dest_port": parsed["dest_port"],
                "proto": parsed["proto"], "bytes": orig_len, "packets": 1,
                "signature": f"pcap {parsed['proto']} {parsed['src_ip']}:{parsed['src_port']} -> "
                             f"{parsed['dest_ip']}:{parsed['dest_port']}",
                "host": "",
            })
    return events


# ── تشخیص نسخه بسته ورودی (فقط برای پورت NetFlow؛ sFlow پورت جداست) ──
def _peek_version(data: bytes) -> str:
    if len(data) < 2:
        return "unknown"
    ver = struct.unpack_from("!H", data, 0)[0]
    return {5: "netflow_v5", 9: "netflow_v9", 10: "ipfix"}.get(ver, f"v{ver}")


# ── هندلرهای UDP ─────────────────────────────────────────
class _FlowUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        try:
            _pkt_q.put_nowait((data, self.client_address))
            _bump("packets_received")
        except queue.Full:
            with _status_lock:
                _status["last_error"] = "packet queue full — dropping"


class _SflowUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        try:
            _sflow_q.put_nowait((data, self.client_address))
            _bump("sflow_packets_received")
        except queue.Full:
            with _status_lock:
                _status["last_error"] = "sflow queue full — dropping"


class _ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = 8192


# ── flusher ها ────────────────────────────────────────────
def _flusher(process_fn, store_fn, flush_interval, batch_size):
    while True:
        time.sleep(flush_interval)
        packets = []
        try:
            while len(packets) < batch_size:
                packets.append(_pkt_q.get_nowait())
        except queue.Empty:
            pass
        if not packets:
            continue

        all_events = []
        for data, peer in packets:
            ver = _peek_version(data)
            exporter_ip = peer[0] if peer else ""
            if ver == "netflow_v5":
                all_events.extend(decode_netflow_v5(data))
            elif ver in ("netflow_v9", "ipfix"):
                all_events.extend(decode_netflow_v9_or_ipfix(data, exporter_ip))
            else:
                with _status_lock:
                    _status["unsupported_versions"][ver] = \
                        _status["unsupported_versions"].get(ver, 0) + 1

        if not all_events:
            continue
        _bump("flows_decoded", len(all_events))
        try:
            events = process_fn(all_events) if process_fn else all_events
            if events and store_fn:
                stored = store_fn(events)
                _bump("flows_stored", stored or 0)
        except Exception as e:
            with _status_lock:
                _status["last_error"] = f"process/store: {e}"


def _sflow_flusher(process_fn, store_fn, flush_interval, batch_size):
    while True:
        time.sleep(flush_interval)
        packets = []
        try:
            while len(packets) < batch_size:
                packets.append(_sflow_q.get_nowait())
        except queue.Empty:
            pass
        if not packets:
            continue

        all_events = []
        for data, _peer in packets:
            all_events.extend(decode_sflow_v5(data))

        if not all_events:
            continue
        _bump("sflow_flows_decoded", len(all_events))
        try:
            events = process_fn(all_events) if process_fn else all_events
            if events and store_fn:
                stored = store_fn(events)
                _bump("flows_stored", stored or 0)
        except Exception as e:
            with _status_lock:
                _status["last_error"] = f"sflow process/store: {e}"


# ── راه‌اندازی ───────────────────────────────────────────
def start_netflow_listener(process_fn=None, store_fn=None,
                           host="0.0.0.0", port=2055,
                           flush_interval=2.0, batch_size=500,
                           enable_sflow=True, sflow_port=6343):
    """
    گیرنده NetFlow (v5/v9/IPFIX) و sFlow را در thread های پس‌زمینه راه می‌اندازد.
    پورت پیش‌فرض NetFlow/IPFIX: 2055  |  sFlow: 6343 (روی پورت جدا، طبق استاندارد)
    process_fn(flow_events)->events   (enrich اختیاری، مشترک بین هر دو منبع)
    store_fn(events)->int             (storage.store_events)
    """
    with _status_lock:
        _status["started_at"] = datetime.now(timezone.utc).isoformat()
        _status["port"] = port

    srv = _ThreadingUDP((host, port), _FlowUDPHandler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="netflow-udp").start()
    _servers.append(srv)
    _status["running"] = True
    print(f"📡 NetFlow/IPFIX collector → udp://{host}:{port}")

    threading.Thread(target=_flusher,
                     args=(process_fn, store_fn, flush_interval, batch_size),
                     daemon=True, name="netflow-flusher").start()
    print(f"✅ NetFlow collector فعال شد (flush هر {flush_interval}s)")

    if enable_sflow:
        with _status_lock:
            _status["sflow_port"] = sflow_port
        sflow_srv = _ThreadingUDP((host, sflow_port), _SflowUDPHandler)
        threading.Thread(target=sflow_srv.serve_forever, daemon=True, name="sflow-udp").start()
        _servers.append(sflow_srv)
        _status["sflow_running"] = True
        print(f"📡 sFlow collector → udp://{host}:{sflow_port}")

        threading.Thread(target=_sflow_flusher,
                         args=(process_fn, store_fn, flush_interval, batch_size),
                         daemon=True, name="sflow-flusher").start()
        print(f"✅ sFlow collector فعال شد (flush هر {flush_interval}s)")


def get_netflow_status() -> dict:
    with _status_lock:
        s = dict(_status)
    s["queue_size"] = _pkt_q.qsize()
    s["sflow_queue_size"] = _sflow_q.qsize()
    return s


# ── سازنده بسته‌های تست (برای تست/شبیه‌سازی، بدون نیاز به ترافیک واقعی) ──
def build_test_v5_packet(flows: list[dict]) -> bytes:
    secs = int(time.time())
    header = _V5_HEADER.pack(5, len(flows), 0, secs, 0, 0, 0, 0, 0)
    body = b""
    for f in flows:
        s = struct.unpack("!I", socket.inet_aton(f["src"]))[0]
        d = struct.unpack("!I", socket.inet_aton(f["dst"]))[0]
        body += _V5_RECORD.pack(
            s, d, 0, 0, 0, f.get("packets", 1), f.get("bytes", 100),
            0, 0, f.get("sport", 1234), f.get("dport", 80), 0,
            f.get("flags", 0), f.get("proto", 6), 0, 0, 0, 0, 0, 0)
    return header + body


def build_test_v9_packets(flows: list[dict], template_id: int = 256) -> tuple[bytes, bytes]:
    """
    یه جفت بسته NetFlow v9 معتبر برای تست می‌سازه: (template_packet, data_packet)
    Template شامل ۴ فیلد: IPV4_SRC_ADDR(8) IPV4_DST_ADDR(12) L4_SRC_PORT(7) L4_DST_PORT(11) PROTOCOL(4)
    """
    secs = int(time.time())
    field_defs = [(8,4), (12,4), (7,2), (11,2), (4,1)]

    # ── بسته Template ──
    tmpl_body = struct.pack("!HH", template_id, len(field_defs))
    for ftype, flen in field_defs:
        tmpl_body += struct.pack("!HH", ftype, flen)
    tmpl_flowset = struct.pack("!HH", 0, 4 + len(tmpl_body)) + tmpl_body
    tmpl_header = _V9_HEADER.pack(9, 1, 0, secs, 1, 100)
    template_packet = tmpl_header + tmpl_flowset

    # ── بسته Data ──
    data_body = b""
    for f in flows:
        s = socket.inet_aton(f["src"])
        d = socket.inet_aton(f["dst"])
        data_body += s + d + struct.pack("!H", f.get("sport",1234)) + \
                     struct.pack("!H", f.get("dport",80)) + struct.pack("!B", f.get("proto",6))
    data_flowset = struct.pack("!HH", template_id, 4 + len(data_body)) + data_body
    data_header = _V9_HEADER.pack(9, 1, 0, secs, 2, 100)
    data_packet = data_header + data_flowset

    return template_packet, data_packet


def build_test_sflow_packet(flows: list[dict]) -> bytes:
    """یه بسته sFlow v5 معتبر با Flow Sample های Raw Packet Header برای تست می‌سازه."""
    agent = socket.inet_aton("192.0.2.1")
    header = struct.pack("!II", 5, 1) + agent + struct.pack("!IIII", 0, 1, 0, len(flows))

    samples = b""
    for f in flows:
        # بسازیم یه فریم Ethernet+IPv4+TCP/UDP خام ساده
        eth = b"\x00"*6 + b"\x11"*6 + struct.pack("!H", 0x0800)
        ip_hdr = bytes([0x45, 0,0,40, 0,0, 0x40,0, 64, f.get("proto",6), 0,0]) + \
                 socket.inet_aton(f["src"]) + socket.inet_aton(f["dst"])
        l4 = struct.pack("!HH", f.get("sport",1234), f.get("dport",80)) + b"\x00"*4
        raw_packet = eth + ip_hdr + l4
        header_len = len(raw_packet)

        flow_data = struct.pack("!IIII", 1, len(raw_packet), 0, header_len) + raw_packet
        pad = (-len(flow_data)) % 4
        flow_data += b"\x00" * pad
        flow_record = struct.pack("!II", 1, len(raw_packet) + 16) + flow_data

        flow_sample_body = struct.pack("!IIIIIIII", 1, 100, 1, 1, 0, 0, 0, 1) + flow_record
        samples += struct.pack("!II", 1, len(flow_sample_body)) + flow_sample_body

    return header + samples


if __name__ == "__main__":
    v5 = build_test_v5_packet([{"src": "1.1.1.1", "dst": "2.2.2.2"}])
    print("v5 decode:", decode_netflow_v5(v5))

    tmpl, dat = build_test_v9_packets([{"src":"3.3.3.3","dst":"4.4.4.4","sport":5555,"dport":443,"proto":6}])
    decode_netflow_v9_or_ipfix(tmpl, "127.0.0.1")  # اول template رو یاد بگیره
    print("v9 decode:", decode_netflow_v9_or_ipfix(dat, "127.0.0.1"))

    sf = build_test_sflow_packet([{"src":"5.5.5.5","dst":"6.6.6.6","sport":9999,"dport":80,"proto":6}])
    print("sflow decode:", decode_sflow_v5(sf))
