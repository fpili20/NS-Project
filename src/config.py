# ==========================================
# 1. CONFIGURAZIONE DATASET: ToN_IoT
# ==========================================
TON_IOT_CONFIG = {
    'file_path': r"../data/Train_Test_Network.csv",
    'has_header': True,
    'target_col': 'type',
    'proto_col': 'proto',
    'mapping': {
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
}

# ==========================================
# 2. CONFIGURAZIONE DATASET: UNSW Processed (Training / Testing set con intestazione)
# ==========================================
UNSW_PROCESSED_CONFIG = {
    'file_path': r"../data/UNSW_NB15_testing-set.csv",
    #'file_path': r"../data/UNSW_NB15_training-set.csv",
    'has_header': True,
    'target_col': 'attack_cat',
    'proto_col': 'proto',
    'mapping': {
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
}

# ==========================================
# 3. CONFIGURAZIONE DATASET: UNSW Raw (File Grezzi con 49 colonne senza header)
# ==========================================
UNSW_NB15_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label"
]

UNSW_RAW_CONFIG = {
    #'file_path': r"../data/UNSW-NB15_1.csv",
    #'file_path': r"../data/UNSW-NB15_2.csv",
    #'file_path': r"../data/UNSW-NB15_3.csv",
    'file_path': r"../data/UNSW-NB15_4.csv",
    'has_header': False,
    'names': UNSW_NB15_RAW_COLUMNS,
    'target_col': 'attack_cat',
    'proto_col': 'proto',
    'mapping': {
        'Normal': 'Benevolent',
        'normal': 'Benevolent',
        'Backdoor': 'Malevolent',
        'backdoor': 'Malevolent',
        'Analysis': 'Malevolent',
        'Fuzzers': 'Malevolent',
        ' Shellcode ': 'Malevolent',
        'Shellcode': 'Malevolent',
        'Reconnaissance': 'Malevolent',
        ' Reconnaissance ': 'Malevolent',
        'Exploits': 'Malevolent',
        'DoS': 'Malevolent',
        'Worms': 'Malevolent',
        'Generic': 'Malevolent',
        ' Fuzzers ': 'Malevolent'
    }
}

# ---------------------------------------------------------
# PROFILO ATTIVO (Scegli quale attivare decommentando la riga)
# ---------------------------------------------------------
#ACTIVE_PROFILE = UNSW_PROCESSED_CONFIG
#ACTIVE_PROFILE = TON_IOT_CONFIG
ACTIVE_PROFILE = UNSW_RAW_CONFIG

# Parametri di raggruppamento e variabili esportate lette dagli altri moduli
SUBSET_SIZE = 500
FILE_PATH = ACTIVE_PROFILE['file_path']
HAS_HEADER = ACTIVE_PROFILE.get('has_header', True)
COLUMN_NAMES = ACTIVE_PROFILE.get('names', None)
TARGET_COL = ACTIVE_PROFILE['target_col']
PROTO_COL = ACTIVE_PROFILE['proto_col']
CATEGORY_MAPPING = ACTIVE_PROFILE['mapping']