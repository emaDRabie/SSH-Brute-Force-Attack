import subprocess
import time
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict

# ======================================================
# CONFIGURATION
# ======================================================
INTERFACE = "ens33"        # Docker: eth0 | Host: ens33 / wlan0
WINDOW_SIZE = 15          # seconds (RECOMMENDED: 8–15)
SLIDE_SIZE = 10            # seconds
SSH_PORT = 22

MODEL_PATH = "ssh_ids_model.pkl"
ALERT_THRESHOLD = 0.90    # ML probability threshold

# ======================================================
# LOAD MODEL (BUNDLE)
# ======================================================
print("[+] Loading ML model...")
bundle = joblib.load(MODEL_PATH)

model = bundle["model"]
FEATURES = bundle["features"]

print("[+] ML model loaded successfully")
print("[+] Features used:")
for f in FEATURES:
    print(" -", f)

print("\n🚨 LIVE SSH IDS (ML MODE)")
print(f"Interface   : {INTERFACE}")
print(f"Window size : {WINDOW_SIZE}s")
print(f"Slide size  : {SLIDE_SIZE}s")
print("=" * 60)

# ======================================================
# START TSHARK
# ======================================================
tshark_cmd = [
    "tshark",
    "-i", INTERFACE,
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


proc = subprocess.Popen(
    tshark_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1
)

# ======================================================
# DATA BUFFER
# ======================================================
packets = []
last_slide = time.time()

# ======================================================
# FLOW KEY (BIDIRECTIONAL)
# ======================================================
def flow_key(src, sport, dst, dport):
    return tuple(sorted([(src, sport), (dst, dport)]))

# ======================================================
# MAIN LOOP
# ======================================================
try:
    for line in proc.stdout:
        parts = line.strip().split(",")
        if len(parts) != 7:
            continue

        ts, src, dst, flags, length, sport, dport = parts

        try:
            ts = float(ts)
            length = int(length) if length else 0
            sport = int(sport)
            dport = int(dport)
            flags = int(flags, 16)
        except ValueError:
            continue

        packets.append((ts, src, dst, sport, dport, length, flags))

        now = time.time()
        if now - last_slide < SLIDE_SIZE:
            continue

        last_slide = now

        # ======================================================
        # WINDOW SLIDING
        # ======================================================
        window_start = ts - WINDOW_SIZE
        packets = [p for p in packets if p[0] >= window_start]

        flows = defaultdict(list)
        for p in packets:
            k = flow_key(p[1], p[3], p[2], p[4])
            flows[k].append(p)

        # ======================================================
        # FEATURE EXTRACTION PER FLOW
        # ======================================================
        for k, pkts in flows.items():
            (src, sport), (dst, dport) = k

            if sport != SSH_PORT and dport != SSH_PORT:
                continue

            times = sorted(p[0] for p in pkts)
            sizes = [p[5] for p in pkts]
            flags_list = [p[6] for p in pkts]

            pkt_count = len(pkts)
            if pkt_count < 3:
                continue

            duration = max(times) - min(times)
            duration = max(duration, 0.0001)

            # -------------------------------
            # Inter-arrival features
            # -------------------------------
            inter_arrivals = np.diff(times)
            mean_ia = np.mean(inter_arrivals)
            std_ia = np.std(inter_arrivals)
            # burstiness = std_ia / mean_ia if mean_ia > 0 else 0

            # -------------------------------
            # TCP flag features
            # -------------------------------
            syn_count = sum(1 for f in flags_list if f & 0x02)
            rst_count = sum(1 for f in flags_list if f & 0x04)
            syn_ratio = syn_count / pkt_count
            # rst_ratio = rst_count / pkt_count

            # -------------------------------
            # Payload features
            # -------------------------------
            # zero_payload_ratio = sum(1 for s in sizes if s == 0) / pkt_count

            flow_count_per_window = len(flows)

            # -------------------------------
            # new features
            # -------------------------------
            zero_payload_count = sum(1 for s in sizes if s == 0)
            unique_packet_sizes = len(set(sizes))
            packet_size_std = np.std(sizes) if pkt_count > 1 else 0


            # ======================================================
            # FEATURE MAP (NAME → VALUE)
            # ======================================================
            feature_map = {
                "mean_inter_arrival": mean_ia,
                "std_inter_arrival": std_ia,
                "packet_count": pkt_count,
                "syn_count": syn_count,
                "rst_count": rst_count,
                "packet_size_std": packet_size_std,
                "unique_packet_sizes": unique_packet_sizes,
                "zero_payload_count": zero_payload_count,
                "syn_ratio": syn_ratio,
                "flow_count_per_window": flow_count_per_window,
            }

            # ======================================================
            # BUILD DATAFRAME (FIXES WARNING)
            # ======================================================
            X = pd.DataFrame(
                [[feature_map[f] for f in FEATURES]],
                columns=FEATURES
            )

            # ======================================================
            # ML PREDICTION
            # ======================================================
            prob = model.predict_proba(X)[0][1]
            results={"timestamp": time.ctime(times[0]), "source_ip": src, "destination_ip": dst, "probability": float(prob), "flow_count_per_window": flow_count_per_window, "attack": "SSH BRUTE-FORCE", "features": feature_map}
            if prob >= ALERT_THRESHOLD:
                print("\n[🚨] SSH BRUTE-FORCE DETECTED!")
                print(results)
                print("-" * 60)
                # print("")
                # print(f"Source IP      : {src}")
                # print(f"Destination IP : {dst}")
                # print(f"Probability    : {prob:.2f}")
                # print(f"Flows/window   : {flow_count_per_window}")
                # print("-" * 60)

except KeyboardInterrupt:
    print("\n[!] IDS stopped by user")
finally:
    proc.terminate()
