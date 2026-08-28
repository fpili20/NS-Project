import pandas as pd
import os
import numpy as np
from matplotlib import pyplot as plt

# ==========================================
# 1. Configurazione Iniziale e Caricamento
# ==========================================
file_path = r"../data/UNSW_NB15_training-set.csv"

# Elenco ufficiale delle 49 colonne dei file raw di UNSW-NB15
UNSW_NB15_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label"
]

try:
    traffic_df = pd.read_csv(file_path, header=None, names=UNSW_NB15_RAW_COLUMNS, low_memory=False)
    print(f"Dataset caricato con successo! Dimensioni: {traffic_df.shape}")
except FileNotFoundError:
    print(f"ERRORE: Impossibile trovare il file al percorso '{file_path}'.")
    exit()

# Mescoliamo le righe per evitare pattern sequenziali
traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)

# ==========================================
# 2. Pulizia e Isolamento dei Campi
# ==========================================
traffic_df['attack_cat'] = traffic_df['attack_cat'].fillna('Normal')
traffic_df['attack_cat'] = traffic_df['attack_cat'].astype(str).str.strip()
traffic_df['proto'] = traffic_df['proto'].astype(str).str.lower().str.strip()

clean_df = traffic_df[["proto", "attack_cat", "label"]].copy()
clean_df = clean_df.rename(columns={'attack_cat': 'type'})

print("\nConteggio dei tipi di traffico prima del raggruppamento:")
print(clean_df['type'].value_counts().sort_index())

# ==========================================
# 3. Data Analysis e Suddivisione in Subset (Foucs su UDP)
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

# Liste per memorizzare le percentuali di UDP
percent_udp_normal = []
percent_udp_malevolent = []

for subset in subsets_normal:
    udp_pkts = len(subset[subset['proto'] == 'udp'])
    percent_udp_normal.append(udp_pkts / subset_size)

for subset in subsets_malevolent:
    udp_pkts = len(subset[subset['proto'] == 'udp'])
    percent_udp_malevolent.append(udp_pkts / subset_size)

print(f"\nGenerati {len(subsets_normal)} subset Benevoli e {len(subsets_malevolent)} subset Malevoli.")


# ==========================================
# 4. Funzione di Plotting
# ==========================================
def plot_proto_percentages(subset_numbers_n, percent_normal, subset_numbers_m, percent_malevolent, proto):
    plt.figure(figsize=(10, 6))

    plt.plot(subset_numbers_n, percent_normal, label='Benevolent', marker='o', linestyle='none', color='blue')
    plt.plot(subset_numbers_m, percent_malevolent, label='Malevolent', marker='x', color='red', linestyle='none')

    plt.xlabel('Subset Number', fontsize=12)
    plt.ylabel(f'Percentage of {proto.upper()}', fontsize=12)
    plt.title(f'Distribuzione Percentuale di {proto.upper()} nei Subset (UNSW-NB15)', fontsize=14, fontweight='bold')

    plt.legend()
    plt.ylim(0, 1.1)
    plt.grid(True, alpha=0.3)
    plt.show()


# Esecuzione del grafico per UDP
plot_proto_percentages(range(len(percent_udp_normal)), percent_udp_normal,
                       range(len(percent_udp_malevolent)), percent_udp_malevolent, 'udp')

# ==========================================
# 5. Classificatore NTC a Soglia Semplice (UDP)
# ==========================================
# Nell'UNSW, il traffico UDP tende ad aumentare durante gli attacchi (media ~41% contro ~25% normale).
# Impostiamo una soglia ipotetica al 35%.
UDP_THRESHOLD = 0.35


def simple_ntc(subset, threshold):
    """
    Classificatore a Soglia Semplice per UDP.
    Se la percentuale di UDP supera la soglia, scatta l'allarme.
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


# Test del classificatore
if len(subsets_malevolent) > 0:
    test_subset = subsets_malevolent[0]
    udp_pct_test = len(test_subset[test_subset['proto'] == 'udp']) / subset_size
    estimated_class = simple_ntc(test_subset, UDP_THRESHOLD)

    print(f"\n[TEST NTC] Sottoinsieme Malevolo analizzato (UDP %: {udp_pct_test:.2f}).")
    print(f"Il classificatore NTC (soglia > {UDP_THRESHOLD}) lo ha valutato come: {estimated_class}")