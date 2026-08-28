import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os

# ==========================================
# 1. Configurazione Globale
# ==========================================
WINDOW_SIZES = [10, 25, 50, 100, 250, 500, 750, 1000, 1500, 2000]
PROTOCOL_TO_ANALYZE = 'tcp'

UNSW_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label"
]

MAPPING = {
    'Normal': 'Benevolent', 'normal': 'Benevolent', 'Backdoor': 'Malevolent',
    'Analysis': 'Malevolent', 'Fuzzers': 'Malevolent', 'Shellcode': 'Malevolent',
    'Reconnaissance': 'Malevolent', 'Exploits': 'Malevolent', 'DoS': 'Malevolent',
    'Worms': 'Malevolent', 'Generic': 'Malevolent', 'ddos': 'Malevolent',
    'dos': 'Malevolent', 'injection': 'Malevolent', 'mitm': 'Malevolent',
    'password': 'Malevolent', 'ransomware': 'Malevolent', 'scanning': 'Malevolent',
    'xss': 'Malevolent'
}

DATASETS = [
    {'name': 'UNSW-NB15 (Raw)', 'path': r'../data/UNSW-NB15_1.csv', 'has_header': False, 'target': 'attack_cat'},
    {'name': 'UNSW-NB15 (Processed)', 'path': r'../data/UNSW_NB15_testing-set.csv', 'has_header': True,
     'target': 'attack_cat'},
    {'name': 'ToN_IoT', 'path': r'../data/Train_Test_Network.csv', 'has_header': True, 'target': 'type'}
]

# ==========================================
# 2. Motore di Estrazione e Calcolo
# ==========================================
plt.figure(figsize=(12, 7))
colors = ['darkorange', 'royalblue', 'forestgreen']

for idx, ds in enumerate(DATASETS):
    if not os.path.exists(ds['path']):
        print(f"Skipping {ds['name']} - File non trovato: {ds['path']}")
        continue

    print(f"Analisi di {ds['name']} in corso...")

    # Caricamento dinamico
    if not ds['has_header']:
        df = pd.read_csv(ds['path'], header=None, names=UNSW_RAW_COLUMNS, low_memory=False)
    else:
        df = pd.read_csv(ds['path'], low_memory=False)

    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Normalizzazione colonne
    target_col = ds['target']
    df[target_col] = df[target_col].fillna('Normal').astype(str).str.strip()
    df['proto'] = df['proto'].astype(str).str.lower().str.strip()

    df['class'] = df[target_col].replace(MAPPING)

    df_benign = df[df['class'] == 'Benevolent']
    df_malicious = df[df['class'] == 'Malevolent']

    separability_scores = []

    for w_size in WINDOW_SIZES:
        sub_b = [df_benign[i:i + w_size] for i in range(0, len(df_benign), w_size) if
                 len(df_benign[i:i + w_size]) == w_size]
        sub_m = [df_malicious[i:i + w_size] for i in range(0, len(df_malicious), w_size) if
                 len(df_malicious[i:i + w_size]) == w_size]

        pct_b = [len(s[s['proto'] == PROTOCOL_TO_ANALYZE]) / w_size for s in sub_b]
        pct_m = [len(s[s['proto'] == PROTOCOL_TO_ANALYZE]) / w_size for s in sub_m]

        # Evitiamo divisioni per zero aggiungendo un epsilon minimo
        mu_b, sig_b = np.mean(pct_b), np.std(pct_b) + 1e-9
        mu_m, sig_m = np.mean(pct_m), np.std(pct_m) + 1e-9

        separability = abs(mu_b - mu_m) / (sig_b + sig_m)
        separability_scores.append(separability)

    plt.plot(WINDOW_SIZES, separability_scores, marker='o', linewidth=2.5, color=colors[idx], label=ds['name'])

# ==========================================
# 3. Finalizzazione Grafico
# ==========================================
plt.title(f'Ottimizzazione Universale del Subset (Protocollo: {PROTOCOL_TO_ANALYZE.upper()})', fontsize=14,
          fontweight='bold')
plt.xlabel('Dimensione del Subset (Numero di Pacchetti)', fontsize=12)
plt.ylabel('Indice di Separabilità delle Gaussiane ($S$)', fontsize=12)
plt.axhline(y=1.0, color='r', linestyle='--', linewidth=2, label='Soglia Minima Affidabilità ($S=1$)')

plt.grid(True, alpha=0.4)
plt.legend(fontsize=11)
plt.tight_layout()
plt.show()