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

        # Shuffling per evitare pattern sequenziali (riattivato)
        traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)
        proto_col = config.PROTO_COL
        target_col = config.TARGET_COL
        mapping = config.CATEGORY_MAPPING

        # Gestione valori mancanti nella colonna target (es. normali a NaN nei raw)
        if target_col in traffic_df.columns:
            traffic_df[target_col] = traffic_df[target_col].fillna('Normal')
        else:
            # Fallback se il target_col configurato non esiste nel df
            target_col = 'attack_cat' if 'attack_cat' in traffic_df.columns else 'type'
            traffic_df[target_col] = traffic_df[target_col].fillna('Normal')

        # Isoliamo i campi utili
        clean_df = traffic_df[[proto_col, target_col]].copy()

        # Pulizia di eventuali spazi bianchi nelle stringhe delle categorie
        clean_df[target_col] = clean_df[target_col].astype(str).str.strip()

        # SALVIAMO IL NOME ORIGINALE DELL'ATTACCO PRIMA DELLA MAPPATURA
        clean_df['original_type'] = clean_df[target_col].copy()

        # Mappatura in macro-classi tramite il dizionario del profilo attivo
        clean_df[target_col] = clean_df[target_col].replace(mapping)

        # Fallback basato sulla colonna label binaria (se presente nei raw di UNSW)
        if 'label' in traffic_df.columns:
            mask_normal = (traffic_df['label'] == 0)
            clean_df.loc[mask_normal, target_col] = 'Benevolent'
            mask_attack = (traffic_df['label'] > 0)
            clean_df.loc[mask_attack, target_col] = 'Malevolent'

        # Normalizzazione finale dei nomi colonna per la pipeline
        clean_df = clean_df.rename(columns={proto_col: 'proto', target_col: 'type'})

        return clean_df

    except FileNotFoundError:
        print(f"[ERRORE] Impossibile trovare il file: '{file_path}'.")
        return None
    except Exception as e:
        print(f"[ERRORE] Si è verificato un errore durante il caricamento: {e}")
        return None


def create_subsets(df, subset_size=None):
    if subset_size is None:
        subset_size = config.SUBSET_SIZE

    # Separiamo in base alla classe standardizzata 'type'
    df_benevolent = df[df['type'] == 'Benevolent']
    df_malevolent = df[df['type'] == 'Malevolent']

    # Creiamo i subset
    subsets_normal = [df_benevolent[i:i + subset_size] for i in range(0, len(df_benevolent), subset_size)]
    subsets_malevolent = [df_malevolent[i:i + subset_size] for i in range(0, len(df_malevolent), subset_size)]

    # Filtriamo i subset scartando quelli incompleti
    subsets_normal = [s for s in subsets_normal if len(s) == subset_size]
    subsets_malevolent = [s for s in subsets_malevolent if len(s) == subset_size]

    return subsets_normal, subsets_malevolent