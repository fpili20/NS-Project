"""
Fast dataset analyzer for IoT networks.

Loads and cleans network traffic data, regroups traffic into macro-classes,
calculates protocol (TCP) distributions, and applies a threshold-based
Network Traffic Classifier (NTC).
"""

import os
import sys

import matplotlib.pyplot as plt
import pandas as pd

# Option 1: Relative path (easier)
# ".." means "go back one folder"
# "/data/" enters the data folder
FILE_PATH = r"../data/Train_Test_Network.csv"


def load_dataset(file_path: str) -> pd.DataFrame:
    """Loads and sorts dataset columns."""
    try:
        df = pd.read_csv(file_path)
        # Sort columns alphabetically
        df = df.sort_index(axis=1)

        print(f"Dataset successfully loaded! Dimensions: {df.shape}")
        print("\nAvailable columns in dataset:\n", df.columns.tolist())
        return df
    except FileNotFoundError:
        print(f"ERROR: Cannot find the file at path '{file_path}'.")
        print("Make sure you moved the CSV file inside the 'data' folder and the name has no extra spaces!")
        sys.exit(1)


def main():
    # 1. Dataset Import and DataFrame Creation
    traffic_df = load_dataset(FILE_PATH)

    # SHUFFLING ROWS IS IMPORTANT TO AVOID HIDDEN SEQUENTIAL PATTERNS
    traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Isolating fields of interest
    # Create a cleaner DataFrame containing only the useful classification fields:
    # 'proto' (protocol), 'type' (attack/normal type), and 'label' (0 normal, 1 malicious).
    clean_df = traffic_df[["proto", "type", "label"]].copy()
    feature = 'type'
    
    # Analyze the distribution of original types in the dataset
    analysis_df = clean_df[feature]
    val_count = analysis_df.value_counts().sort_index()
    print("\nTraffic types count before grouping:\n", val_count)
    
    numero_righe = clean_df.shape[0]
    print(f"Method 1 - The clean_df DataFrame contains: {numero_righe} rows.")
    
    # Try to extract some statistics
    type_proto_counts = clean_df.groupby('type')['proto'].value_counts().unstack(fill_value=0)
    print(type_proto_counts)

    # Data Analysis

    # 1. Grouping into macro-classes (Benevolent vs Malevolent)
    # Map the various specific attack types into a single 'Malevolent' category,
    # and 'normal' traffic into 'Benevolent'.
    category_mapping = {
        'normal': 'Benevolent',
        'backdoor': 'Malevolent',
        'ddos': 'Malevolent',
        'dos': 'Malevolent',
        'injection': 'Malevolent',
        'mitm': 'Malevolent',
        'password': 'Malevolent',
        'ransomware': 'Malevolent',
        'scanning': 'Malevolent',
        'xss': 'Malevolent'
    }

    # Apply the mapping by overwriting the 'type' column
    clean_df['type'] = clean_df['type'].replace(category_mapping)
    
    # 2. Subset splitting and statistical calculation on TCP protocol
    subset_size = 1000  # Split traffic into blocks of 1000 packets

    # Create two separate dataframes for benevolent and malicious traffic
    df_benevolent = clean_df[clean_df['type'] == 'Benevolent']
    df_malevolent = clean_df[clean_df['type'] == 'Malevolent']

    # Generate a list of subsets for each category
    subsets_normal = [df_benevolent[i:i + subset_size] for i in range(0, len(df_benevolent), subset_size)]
    subsets_malevolent = [df_malevolent[i:i + subset_size] for i in range(0, len(df_malevolent), subset_size)]

    percent_tcp_normal = []
    percent_tcp_malevolent = []

    # Calculate TCP packet percentage for Benevolent subsets
    for subset in subsets_normal:
        total_pkts = len(subset)
        if total_pkts > 0:
            tcp_pkts = len(subset[subset['proto'] == 'tcp'])
            percent_tcp_normal.append(tcp_pkts / total_pkts)

    # Calculate TCP packet percentage for Malevolent subsets
    for subset in subsets_malevolent:
        total_pkts = len(subset)
        if total_pkts > 0:
            tcp_pkts = len(subset[subset['proto'] == 'tcp'])
            percent_tcp_malevolent.append(tcp_pkts / total_pkts)

    # Call function to show graph
    plot_proto_percentages(
        list(range(len(percent_tcp_normal))), percent_tcp_normal,
        list(range(len(percent_tcp_malevolent))), percent_tcp_malevolent, 
        'tcp'
    )

    # Validate NTC: Test the classifier on the very first malicious subset available
    if subsets_malevolent:
        test_subset = subsets_malevolent[0]
        estimated_class = simple_ntc(test_subset, TCP_THRESHOLD)
        print(f"\nThe NTC classifier evaluated the test subset as: {estimated_class}")


# 3. Plotting Function to visualize the difference between the two classes
def plot_proto_percentages(subset_numbers_n: list, percent_normal: list, 
                           subset_numbers_m: list, percent_malevolent: list, proto: str):
    """Plots the percentage distribution of a specific protocol across subsets."""
    plt.figure(figsize=(10, 6))

    # Plot the percentages. Use different colors and markers to distinguish them.
    plt.plot(subset_numbers_n, percent_normal, label='Benevolent', marker='o', linestyle='none', color='blue')
    plt.plot(subset_numbers_m, percent_malevolent, label='Malevolent', marker='x', color='red', linestyle='none')

    plt.xlabel('Subset Number')
    plt.ylabel(f'Percentage of {proto.upper()}')
    plt.title(f'Percentage of {proto.upper()} in "proto" for each class in subset')

    plt.legend()
    # Set the Y-axis limit between 0 and 1 (representing percentages from 0% to 100%)
    plt.ylim(0, 1.1)
    plt.grid(True)
    plt.show()


# ==========================================
# STEP 3: Development of an NTC
# ==========================================

# Threshold Definition
# Based on visual and statistical observation (graphs), suppose we noticed
# that malicious traffic has a very high TCP density, for instance > 70%.
TCP_THRESHOLD = 0.70


def simple_ntc(subset: pd.DataFrame, threshold: float) -> str:
    """
    Simple Threshold Classifier.
    Evaluates a subset of packets and estimates the traffic class (NTC).
    """
    total_pkts = len(subset)
    if total_pkts == 0:
        return "Unknown"

    # Count TCP packets
    tcp_pkts = len(subset[subset['proto'] == 'tcp'])
    tcp_percent = tcp_pkts / total_pkts

    # Threshold-based classification: if TCP % exceeds the threshold, it is labeled as Malevolent
    if tcp_percent > threshold:
        return "Malevolent"
    else:
        return "Benevolent"


if __name__ == "__main__":
    main()
