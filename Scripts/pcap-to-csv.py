import sys
import subprocess
import pandas as pd
import numpy as np
import os
from collections import defaultdict

# ==============================
# ARGUMENTS
# ==============================
if len(sys.argv) != 5:
    print("Usage: python3 sc_multi.py <pcap_dir> <output.csv> <window_size> <label>")
    sys.exit(1)

PCAP_DIR = sys.argv[1]
OUTPUT_CSV = sys.argv[2]
WINDOW_SIZE = int(sys.argv[3])
LABEL = int(sys.argv[4])   # 1 = attack, 0 = normal

SSH_PORT = 22

print(f"[+] PCAP directory : {PCAP_DIR}")
print(f"[+] Window size    : {WINDOW_SIZE}s")
print(f"[+] Label          : {LABEL}")

# ==============================
# COLLECT PCAP FILES
# ==============================
pcap_files = [
    os.path.join(PCAP_DIR, f)
    for f in os.listdir(PCAP_DIR)
    if f.endswith(".pcap") or f.endswith(".pcapng")
]

if not pcap_files:
    print("[-] No pcap/pcapng files found")
    sys.exit(1)

print(f"[+] Found {len(pcap_files)} pcap files")

# ==============================
# FLOW KEY
# ==============================
def flow_key(src, sport, dst, dport):
    return tuple(sorted([(src, sport), (dst, dport)]))

# ==============================
# MAIN STORAGE
# ==============================
rows = []
global_window_id = 0

# ==============================
# PROCESS EACH PCAP
# ==============================
for pcap in pcap_files:
    print(f"[+] Processing: {pcap}")

    tshark_cmd = [
        "tshark",
        "-r", pcap,
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

    result = subprocess.run(tshark_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[-] tshark error in {pcap}")
        continue

    packets = []
    lines = result.stdout.strip().split("\n")
    
    # Skip empty outputs
    if len(lines) == 1 and lines[0] == '':
        continue

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

    if not packets:
        continue

    start_time = packets[0][0]
    end_time = packets[-1][0]
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

            # Basic Arrays
            times = sorted([p[0] for p in pkts])
            sizes = [p[5] for p in pkts]
            flags_list = [p[6] for p in pkts]
            
            # --- NEW & UPDATED FEATURES ---
            
            # 1. Packet Count (Volume)
            pkt_count = len(pkts)

            # 2. Packet Size Variance (Using Std Dev as it is more stable for ML)
            packet_size_std = np.std(sizes) if pkt_count > 1 else 0

            # 3. Unique Packet Sizes
            unique_packet_sizes = len(set(sizes))

            # 4. Zero Payload Count (Converted from Ratio)
            zero_payload_count = sum(1 for s in sizes if s == 0)

            # Existing Time Features (Kept mean/std/duration, removed burstiness)
            duration = max(times) - min(times) if pkt_count > 1 else 0.0001
            inter_arrivals = np.diff(times) if pkt_count > 1 else [0]
            mean_ia = np.mean(inter_arrivals)
            std_ia = np.std(inter_arrivals)
            
            # Existing Flag Counts (Kept counts, removed ratios)
            syn_count = sum(1 for f in flags_list if f & 0x02)
            rst_count = sum(1 for f in flags_list if f & 0x04)

            rows.append({
                "window_id": global_window_id,
                "src_ip": src,
                "dst_ip": dst,
                # Time
                "mean_inter_arrival": mean_ia,
                "std_inter_arrival": std_ia,
                # Counts
                "packet_count": pkt_count,           # NEW
                "syn_count": syn_count,
                "rst_count": rst_count,
                "zero_payload_count": zero_payload_count, # UPDATED
                # Size / Shape
                "packet_size_std": packet_size_std,       # NEW
                "unique_packet_sizes": unique_packet_sizes, # NEW
                # Meta
                "flow_count_per_window": len(flows),
                "label": LABEL
            })

        global_window_id += 1
        t += WINDOW_SIZE

# ==============================
# SAVE CSV
# ==============================
df = pd.DataFrame(rows)
df.to_csv(OUTPUT_CSV, index=False)

print(f"[✅] Dataset saved to: {OUTPUT_CSV}")
print(f"[✔] Total rows: {len(df)}")