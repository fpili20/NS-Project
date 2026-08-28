"""
Fast dataset analyzer for the UNSW-NB15 dataset.

This script loads the UNSW-NB15 dataset, cleans and maps traffic categories,
divides the dataset into subsets, and calculates the percentage of UDP traffic
to build a simple Network Traffic Classifier (NTC) based on a threshold.
"""

import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# ==========================================
# 1. Initial Configuration and Loading
# ==========================================
FILE_PATH = r"../data/UNSW_NB15_training-set.csv"

# Official list of 49 columns for UNSW-NB15 raw files
UNSW_NB15_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label"
]


def load_dataset(file_path: str) -> pd.DataFrame:
    """Loads the dataset from a CSV file."""
    try:
        df = pd.read_csv(file_path, header=None, names=UNSW_NB15_RAW_COLUMNS, low_memory=False)
        print(f"Dataset successfully loaded! Dimensions: {df.shape}")
        return df
    except FileNotFoundError:
        print(f"ERROR: Cannot find the file at path '{file_path}'.")
        sys.exit(1)


def main():
    traffic_df = load_dataset(FILE_PATH)

    # Shuffle rows to avoid sequential patterns
    traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # ==========================================
    # 2. Cleaning and Isolating Fields
    # ==========================================
    traffic_df['attack_cat'] = traffic_df['attack_cat'].fillna('Normal')
    traffic_df['attack_cat'] = traffic_df['attack_cat'].astype(str).str.strip()
    traffic_df['proto'] = traffic_df['proto'].astype(str).str.lower().str.strip()

    clean_df = traffic_df[["proto", "attack_cat", "label"]].copy()
    clean_df = clean_df.rename(columns={'attack_cat': 'type'})

    print("\nTraffic types count before grouping:")
    print(clean_df['type'].value_counts().sort_index())

    # ==========================================
    # 3. Data Analysis and Subset Splitting (UDP Focus)
    # ==========================================
    category_mapping = {
        'Normal': 'Benevolent',
        'Backdoor': 'Malevolent',
        'Analysis': 'Malevolent',
        'Fuzzers': 'Malevolent',
        'Shellcode': 'Malevolent',
        'Reconnaissance': 'Malevolent',
        'Exploits': 'Malevolent',
        'DoS': 'Malevolent',
        'Worms': 'Malevolent',
        'Generic': 'Malevolent'
    }

    clean_df['type'] = clean_df['type'].replace(category_mapping)

    subset_size = 1000

    df_benevolent = clean_df[clean_df['type'] == 'Benevolent']
    df_malevolent = clean_df[clean_df['type'] == 'Malevolent']

    subsets_normal = [df_benevolent[i:i + subset_size] for i in range(0, len(df_benevolent), subset_size)]
    subsets_normal = [s for s in subsets_normal if len(s) == subset_size]

    subsets_malevolent = [df_malevolent[i:i + subset_size] for i in range(0, len(df_malevolent), subset_size)]
    subsets_malevolent = [s for s in subsets_malevolent if len(s) == subset_size]

    # Lists to store UDP percentages
    percent_udp_normal = []
    percent_udp_malevolent = []

    for subset in subsets_normal:
        udp_pkts = len(subset[subset['proto'] == 'udp'])
        percent_udp_normal.append(udp_pkts / subset_size)

    for subset in subsets_malevolent:
        udp_pkts = len(subset[subset['proto'] == 'udp'])
        percent_udp_malevolent.append(udp_pkts / subset_size)

    print(f"\nGenerated {len(subsets_normal)} Benevolent subsets and {len(subsets_malevolent)} Malevolent subsets.")

    # Execute plot for UDP
    plot_proto_percentages(
        list(range(len(percent_udp_normal))), percent_udp_normal,
        list(range(len(percent_udp_malevolent))), percent_udp_malevolent,
        'udp'
    )

    # Test the classifier
    if subsets_malevolent:
        test_subset = subsets_malevolent[0]
        udp_pct_test = len(test_subset[test_subset['proto'] == 'udp']) / subset_size
        estimated_class = simple_ntc(test_subset, UDP_THRESHOLD)

        print(f"\n[NTC TEST] Analyzed Malevolent subset (UDP %: {udp_pct_test:.2f}).")
        print(f"The NTC classifier (threshold > {UDP_THRESHOLD}) evaluated it as: {estimated_class}")


# ==========================================
# 4. Plotting Function
# ==========================================
def plot_proto_percentages(subset_numbers_n: list, percent_normal: list,
                           subset_numbers_m: list, percent_malevolent: list, proto: str):
    """Plots the percentage distribution of a specific protocol across subsets."""
    plt.figure(figsize=(10, 6))

    plt.plot(subset_numbers_n, percent_normal, label='Benevolent', marker='o', linestyle='none', color='blue')
    plt.plot(subset_numbers_m, percent_malevolent, label='Malevolent', marker='x', color='red', linestyle='none')

    plt.xlabel('Subset Number', fontsize=12)
    plt.ylabel(f'Percentage of {proto.upper()}', fontsize=12)
    plt.title(f'Percentage Distribution of {proto.upper()} in Subsets (UNSW-NB15)', fontsize=14, fontweight='bold')

    plt.legend()
    plt.ylim(0, 1.1)
    plt.grid(True, alpha=0.3)
    plt.show()


# ==========================================
# 5. Simple Threshold NTC Classifier (UDP)
# ==========================================
# In UNSW, UDP traffic tends to increase during attacks (avg ~41% vs ~25% normal).
# We set a hypothetical threshold at 35%.
UDP_THRESHOLD = 0.35


def simple_ntc(subset: pd.DataFrame, threshold: float) -> str:
    """
    Simple Threshold Classifier for UDP.
    If the percentage of UDP exceeds the threshold, an alarm is triggered.
    """
    total_pkts = len(subset)
    if total_pkts == 0:
        return "Unknown"

    udp_pkts = len(subset[subset['proto'] == 'udp'])
    udp_percent = udp_pkts / total_pkts

    if udp_percent > threshold:
        return "Malevolent"
    else:
        return "Benevolent"


if __name__ == "__main__":
    main()
