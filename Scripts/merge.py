import pandas as pd
import glob
import sys
import os

# ===============================
# CONFIG
# ===============================
if len(sys.argv) != 3:
    print(f"Usage: python {sys.argv[0]} <folder_path> <output_filename.csv>")
    sys.exit(1)

INPUT_FOLDER = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

# ===============================
# 1. Find all CSV files
# ===============================
# Join the path correctly to find *.csv inside the folder
csv_files = glob.glob(os.path.join(INPUT_FOLDER, "*.csv"))

if not csv_files:
    print(f"[!] No CSV files found in folder: {INPUT_FOLDER}")
    sys.exit(1)

print(f"[+] Found {len(csv_files)} CSV files. Merging...")

# ===============================
# 2. Read and Concatenate
# ===============================
df_list = []

for file in csv_files:
    # Skip the output file if it already exists in the folder to avoid duplication
    if os.path.basename(file) == os.path.basename(OUTPUT_FILE):
        continue
        
    try:
        # Read individual CSV
        df = pd.read_csv(file)
        # Optional: Add a column to track which file the data came from
        # df["source_file"] = os.path.basename(file)
        df_list.append(df)
        print(f"   -> Added: {os.path.basename(file)} ({len(df)} rows)")
    except pd.errors.EmptyDataError:
        print(f"   [!] Skipped empty file: {file}")

# Merge all into one DataFrame
if df_list:
    merged_df = pd.concat(df_list, ignore_index=True)
    
    # ===============================
    # 3. Save Output
    # ===============================
    merged_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[✅] Successfully merged {len(merged_df)} rows into: {OUTPUT_FILE}")
else:
    print("\n[!] No valid data found to merge.")
