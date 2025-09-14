#!/usr/bin/env python3
"""
cli_sniffer_simple.py

Minimal CLI packet sniffer + anomaly detector.
Requirements: Python3, scapy 

Usage:
  sudo python3 cli_sniffer_simple.py --iface lo
  sudo python3 cli_sniffer_simple.py --iface eth0 --window 10 --portscan 40
"""

import argparse, sqlite3, time, logging
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

# ---------- Configurable defaults ----------
DB_PATH = "traffic.db"
ALERT_LOG = "alerts.log"
BATCH_COMMIT = 100   # commit every N inserts

DEFAULT_WINDOW = 10
DEFAULT_PORTSCAN = 100
DEFAULT_PKT_FLOOD = 2000
DEFAULT_BYTE_FLOOD = 5000000
# -------------------------------------------

logger = logging.getLogger("sniffer")
logging.basicConfig(filename=ALERT_LOG, level=logging.INFO, format="%(asctime)s %(message)s")


# ---------- DB (single shared connection, batched commits) ----------
class DB:
    def __init__(self, path=DB_PATH, enable=True):
        self.enable = enable
        if not enable:
            self.conn = None
            self.cur = None
            return
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.cur = self.conn.cursor()
        self._init_schema()
        self._pending = 0
        self._pkt_stmt = "INSERT INTO packets (ts, src, dst, src_port, dst_port, proto, length, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        self._alert_stmt = "INSERT INTO alerts (ts, type, src, details) VALUES (?, ?, ?, ?)"

    def _init_schema(self):
        self.cur.executescript("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, src TEXT, dst TEXT, src_port INTEGER, dst_port INTEGER, proto TEXT, length INTEGER, flags TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ts ON packets(ts);
        CREATE INDEX IF NOT EXISTS idx_src ON packets(src);
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, type TEXT, src TEXT, details TEXT
        );
        """)
        self.conn.commit()

    def insert_packet(self, row):
        if not self.enable: return
        self.cur.execute(self._pkt_stmt, row)
        self._pending += 1
        if self._pending >= BATCH_COMMIT:
            self.conn.commit()
            self._pending = 0

    def insert_alert(self, row):
        if not self.enable: return
        self.cur.execute(self._alert_stmt, row)
        self.conn.commit()

    def close(self):
        if not self.enable or not self.conn: return
        if self._pending:
            self.conn.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# ---------- Sliding-window detector ----------
class SlidingDetector:
    """
    Maintains for each src:
      - deque of (ts, dst_port, length)
      - count, byte_sum, port_counts (dict) for O(1) updates on append/evict
    """
    def __init__(self, window=DEFAULT_WINDOW, portscan_th=DEFAULT_PORTSCAN,
                 pkt_th=DEFAULT_PKT_FLOOD, byte_th=DEFAULT_BYTE_FLOOD, db=None):
        self.window = float(window)
        self.portscan_th = int(portscan_th)
        self.pkt_th = int(pkt_th)
        self.byte_th = int(byte_th)
        self.db = db
        self.data = defaultdict(lambda: {"dq": deque(), "count": 0, "bytes": 0, "port_counts": defaultdict(int)})

    def add(self, ts, src, dst_port, length):
        entry = self.data[src]
        dq = entry["dq"]
        dq.append((ts, dst_port, length))
        entry["count"] += 1
        entry["bytes"] += length
        if dst_port is not None:
            entry["port_counts"][dst_port] += 1
        self._evict_old(entry, ts)
        self._check(src, entry)

    def _evict_old(self, entry, now):
        dq = entry["dq"]
        while dq and (now - dq[0][0]) > self.window:
            _, port, length = dq.popleft()
            entry["count"] -= 1
            entry["bytes"] -= length
            if port is not None:
                pc = entry["port_counts"]
                pc[port] -= 1
                if pc[port] <= 0:
                    del pc[port]

    def _check(self, src, entry):
        distinct_ports = len(entry["port_counts"])
        count = entry["count"]
        total_bytes = entry["bytes"]
        now = time.time()

        if distinct_ports >= self.portscan_th:
            self._alert(now, "PORT_SCAN", src, f"{distinct_ports} distinct dst ports in last {self.window}s")
        if count >= self.pkt_th:
            self._alert(now, "PKT_FLOOD", src, f"{count} packets in last {self.window}s")
        if total_bytes >= self.byte_th:
            self._alert(now, "BYTE_FLOOD", src, f"{total_bytes} bytes in last {self.window}s")

    def _alert(self, ts, typ, src, details):
        msg = f"{typ} | src={src} | {details}"
        logger.info(msg)
        print(f"[ALERT] {datetime.fromtimestamp(ts).isoformat()} {msg}")
        if self.db:
            self.db.insert_alert((ts, typ, src, details))


# ---------- Packet processing ----------
def process_packet(pkt, detector, db, store_db=True):
    ts = time.time()
    if IP not in pkt:  # only IP packets
        return
    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    length = len(pkt)
    src_port = dst_port = None
    flags = ""
    if TCP in pkt:
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        flags = str(pkt[TCP].flags)
        proto = "TCP"
    elif UDP in pkt:
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
        proto = "UDP"
    else:
        proto = f"IP({ip.proto})"

    if store_db:
        try:
            db.insert_packet((ts, src, dst, src_port, dst_port, proto, length, flags))
        except Exception as e:
            print(f"[WARN] DB insert failed: {e}")

    print(f"{datetime.fromtimestamp(ts).strftime('%H:%M:%S')} {src}:{src_port or '-'} -> {dst}:{dst_port or '-'} {proto} len={length} flags={flags}")

    detector.add(ts, src, dst_port, length)


# ---------- CLI and main ----------
def parse_args():
    p = argparse.ArgumentParser(description="Minimal CLI packet sniffer + anomaly detector")
    p.add_argument("--iface", "-i", default=None)
    p.add_argument("--filter", "-f", default=None)
    p.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    p.add_argument("--portscan", type=int, default=DEFAULT_PORTSCAN)
    p.add_argument("--pkt-th", type=int, default=DEFAULT_PKT_FLOOD)
    p.add_argument("--byte-th", type=int, default=DEFAULT_BYTE_FLOOD)
    p.add_argument("--no-db", action="store_true", help="Do not persist packets to SQLite")
    p.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = forever)")
    return p.parse_args()

def main():
    args = parse_args()
    print("=== CLI Packet Sniffer (simple) ===")
    if args.iface: print(f"Interface: {args.iface}")
    if args.filter: print(f"BPF filter: {args.filter}")
    print("Press Ctrl+C to stop\n")

    with DB(enable=not args.no_db) as db:
        detector = SlidingDetector(window=args.window, portscan_th=args.portscan, pkt_th=args.pkt_th, byte_th=args.byte_th, db=db if not args.no_db else None)
        try:
            sniff_kwargs = {"prn": lambda pkt: process_packet(pkt, detector, db, store_db=not args.no_db), "store": False}
            if args.iface: sniff_kwargs["iface"] = args.iface
            if args.filter: sniff_kwargs["filter"] = args.filter
            if args.count and args.count > 0: sniff_kwargs["count"] = args.count
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            print("\nStopped by user.")
        except PermissionError:
            print("Permission error: run with sudo or set capabilities.")
        except Exception as e:
            print(f"Sniff error: {e}")
        finally:
            print("Exiting. Last alerts (tail of alerts.log):")
            try:
                with open(ALERT_LOG, "r") as f:
                    for line in f.readlines()[-10:]:
                        print(line.rstrip())
            except FileNotFoundError:
                print("(no alerts logged)")

if __name__ == "__main__":

    main()
