import sys
import subprocess
import pandas as pd
import numpy as np
from collections import defaultdict

# ==============================
# ARGUMENTS
# ==============================
if len(sys.argv) != 5:
    print("Usage: python3 sc.py <pcap> <output.csv> <window_size> <label>")
    sys.exit(1)

PCAP_FILE = sys.argv[1]
OUTPUT_CSV = sys.argv[2]
WINDOW_SIZE = int(sys.argv[3])
LABEL = int(sys.argv[4])   # 1 = brute-force, 0 = normal

SSH_PORT = 22

print(f"[+] Processing PCAP: {PCAP_FILE}")
print(f"[+] Window size   : {WINDOW_SIZE}s")
print(f"[+] Label         : {LABEL}")

# ==============================
# RUN TSHARK
# ==============================
tshark_cmd = [
    "tshark",
    "-r", PCAP_FILE,
    "-Y", "tcp",
    "-T", "fields",
    "-E", "separator=,",
    "-e", "frame.time_epoch",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "tcp.flags",
    "-e", "tcp.len",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport"
]

print("[+] Extracting packets...")
result = subprocess.run(tshark_cmd, capture_output=True, text=True)

if result.returncode != 0:
    print("[-] tshark error")
    sys.exit(1)

lines = result.stdout.strip().split("\n")

packets = []

for line in lines:
    parts = line.split(",")
    if len(parts) != 7:
        continue

    ts, src, dst, flags, length, sport, dport = parts

    packets.append((
        float(ts),
        src,
        dst,
        int(sport),
        int(dport),
        int(length) if length else 0,
        int(flags, 16)
    ))

# ==============================
# FLOW KEY
# ==============================
def flow_key(src, sport, dst, dport):
    return tuple(sorted([(src, sport), (dst, dport)]))

# ==============================
# WINDOW PROCESSING
# ==============================
rows = []

start_time = packets[0][0]
end_time = packets[-1][0]

window_id = 0
t = start_time

while t <= end_time:
    window_packets = [p for p in packets if t <= p[0] < t + WINDOW_SIZE]

    flows = defaultdict(list)
    for p in window_packets:
        k = flow_key(p[1], p[3], p[2], p[4])
        flows[k].append(p)

    for k, pkts in flows.items():
        src, sport = k[0]
        dst, dport = k[1]

        if sport != SSH_PORT and dport != SSH_PORT:
            continue

        times = sorted([p[0] for p in pkts])
        sizes = [p[5] for p in pkts]
        flags_list = [p[6] for p in pkts]

        pkt_count = len(pkts)
        duration = max(times) - min(times) if pkt_count > 1 else 0.0001

        # Inter-arrival
        inter_arrivals = np.diff(times) if pkt_count > 1 else [0]
        mean_ia = np.mean(inter_arrivals)
        std_ia = np.std(inter_arrivals)
        burstiness = std_ia / mean_ia if mean_ia > 0 else 0

        # TCP flags
        syn_count = sum(1 for f in flags_list if f & 0x02)
        rst_count = sum(1 for f in flags_list if f & 0x04)

        syn_ratio = syn_count / pkt_count
        rst_ratio = rst_count / pkt_count

        zero_payload_ratio = sum(1 for s in sizes if s == 0) / pkt_count

        flow_count_per_window = len(flows)

        rows.append({
            "window_id": window_id,
            "src_ip": src,
            "dst_ip": dst,
            "mean_inter_arrival": mean_ia,
            "std_inter_arrival": std_ia,
            "burstiness": burstiness,
            "syn_count": syn_count,
            "rst_count": rst_count,
            "syn_ratio": syn_ratio,
            "rst_ratio": rst_ratio,
            "zero_payload_ratio": zero_payload_ratio,
            "flow_count_per_window": flow_count_per_window,
            "label": LABEL
        })

    window_id += 1
    t += WINDOW_SIZE

# ==============================
# SAVE CSV
# ==============================
df = pd.DataFrame(rows)

df.to_csv(OUTPUT_CSV, index=False)

print(f"[✅] Dataset saved to: {OUTPUT_CSV}")
print(f"[✔] Total rows: {len(df)}")

