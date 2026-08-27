# ==========================================
# CONFIGURAZIONE DATASET: ToN_IoT
# ==========================================
TON_IOT_CONFIG = {
    'file_path': r"../data/Train_Test_Network.csv",
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
# CONFIGURAZIONE DATASET: UNSW-NB15 (Nuovo)
# ==========================================
UNSW_NB15_CONFIG = {
    'file_path': r"../data/UNSW_NB15_testing-set.csv",
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

# ---------------------------------------------------------
# PROFILO ATTIVO
# Scegli qui quale configurazione usare cambiando la variabile.
# Esempio: ACTIVE_PROFILE = TON_IOT_CONFIG oppure BOT_IOT_CONFIG
# ---------------------------------------------------------
#ACTIVE_PROFILE = TON_IOT_CONFIG
ACTIVE_PROFILE = UNSW_NB15_CONFIG


# Parametri di raggruppamento
SUBSET_SIZE = 1000

# Variabili esportate (lette dagli altri file in automatico)
FILE_PATH = ACTIVE_PROFILE['file_path']
TARGET_COL = ACTIVE_PROFILE['target_col']
PROTO_COL = ACTIVE_PROFILE['proto_col']
CATEGORY_MAPPING = ACTIVE_PROFILE['mapping']