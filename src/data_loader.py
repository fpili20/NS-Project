import pandas as pd
import config

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


def load_and_preprocess(file_path=None):
    if file_path is None:
        file_path = config.FILE_PATH

    try:
        # Determiniamo se il file ha o meno l'header in base al profilo attivo
        has_header = getattr(config, 'HAS_HEADER', True)

        if has_header:
            traffic_df = pd.read_csv(file_path, low_memory=False)
        else:
            traffic_df = pd.read_csv(file_path, header=None, names=UNSW_NB15_RAW_COLUMNS, low_memory=False)

        print(f"[Data Loader] Dataset caricato! Dimensioni: {traffic_df.shape}")

        proto_col = config.PROTO_COL
        traffic_df[proto_col] = traffic_df[proto_col].astype(str).str.lower().str.strip()

        # Filtriamo il DataFrame tenendo solo i tre protocolli di interesse
        protocols_target = ['tcp', 'udp', 'icmp']
        traffic_df = traffic_df[traffic_df[proto_col].isin(protocols_target)].copy()

        print(f"[Data Loader] Dimensioni dopo il filtro TCP/UDP/ICMP: {traffic_df.shape}")

        # Stampa in console la quantità dei protocolli filtrati
        print("\n--- Quantità dei Protocolli (Solo TCP, UDP, ICMP) ---")
        proto_counts = traffic_df[proto_col].value_counts()
        for proto, count in proto_counts.items():
            print(f"  - {str(proto).upper()}: {count} pacchetti")
        print("---------------------------------------------------\n")

        # Shuffling globale (riattivato come richiesto)
        traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)
        proto_col = config.PROTO_COL
        target_col = config.TARGET_COL
        mapping = config.CATEGORY_MAPPING

        # Gestione valori mancanti
        if target_col in traffic_df.columns:
            traffic_df[target_col] = traffic_df[target_col].fillna('Normal')
        else:
            target_col = 'attack_cat' if 'attack_cat' in traffic_df.columns else 'type'
            traffic_df[target_col] = traffic_df[target_col].fillna('Normal')

        clean_df = traffic_df[[proto_col, target_col]].copy()
        clean_df[target_col] = clean_df[target_col].astype(str).str.strip()
        clean_df['original_type'] = clean_df[target_col].copy()
        clean_df[target_col] = clean_df[target_col].replace(mapping)

        if 'label' in traffic_df.columns:
            mask_normal = (traffic_df['label'] == 0)
            clean_df.loc[mask_normal, target_col] = 'Benevolent'
            mask_attack = (traffic_df['label'] > 0)
            clean_df.loc[mask_attack, target_col] = 'Malevolent'

        clean_df = clean_df.rename(columns={proto_col: 'proto', target_col: 'type'})
        return clean_df

    except FileNotFoundError:
        print(f"[ERRORE] Impossibile trovare il file: '{file_path}'.")
        return None
    except Exception as e:
        print(f"[ERRORE] Si è verificato un errore durante il caricamento: {e}")
        return None

def create_subsets(df, subset_size=None):
    """
    Crea subset dividendoli dal dataframe globale GIA' MISTO.
    CORREZIONE: non effettua più la separazione forzata pre-chunking.
    I subset restituiti non sono divisi in liste "normali" e "malevoli",
    perché la classificazione va fatta successivamente.
    Restituisce un'unica lista di subset eterogenei.
    """
    if subset_size is None:
        subset_size = config.SUBSET_SIZE

    num_subsets = len(df) // subset_size
    subsets = [df.iloc[i * subset_size : (i + 1) * subset_size] for i in range(num_subsets)]
    
    return subsets