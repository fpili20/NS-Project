import pandas as pd
from config import CATEGORY_MAPPING, SUBSET_SIZE, PROTO_COL, TARGET_COL


def load_and_preprocess(file_path):
    try:
        # 1. Carica il file
        traffic_df = pd.read_csv(file_path)
        traffic_df = traffic_df.sort_index(axis=1)

        print(f"[Data Loader] Dataset caricato! Dimensioni: {traffic_df.shape}")

        # 2. Shuffling per evitare pattern sequenziali
        traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)

        # 3. Estrazione dinamica: Prende solo la colonna del protocollo e quella del target lette da config.py
        clean_df = traffic_df[[PROTO_COL, TARGET_COL]].copy()

        # 4. Mappatura dinamica: Trasforma gli attacchi in Malevolent e il traffico lecito in Benevolent
        clean_df[TARGET_COL] = clean_df[TARGET_COL].replace(CATEGORY_MAPPING)

        # 5. Normalizzazione dei nomi delle colonne per far funzionare il resto del codice senza intoppi
        clean_df = clean_df.rename(columns={PROTO_COL: 'proto', TARGET_COL: 'type'})

        return clean_df

    except FileNotFoundError:
        print(f"[ERRORE] Impossibile trovare il file: '{file_path}'.")
        return None


def create_subsets(df, subset_size=SUBSET_SIZE):
    # La colonna ora si chiama in modo standardizzato 'type'
    df_benevolent = df[df['type'] == 'Benevolent']
    df_malevolent = df[df['type'] == 'Malevolent']

    # Creiamo i subset
    subsets_normal = [df_benevolent[i:i + subset_size] for i in range(0, len(df_benevolent), subset_size)]
    subsets_malevolent = [df_malevolent[i:i + subset_size] for i in range(0, len(df_malevolent), subset_size)]

    # Rimuoviamo eventuali subset troppo piccoli alla fine (opzionale ma consigliato per coerenza statistica)
    subsets_normal = [s for s in subsets_normal if len(s) == subset_size]
    subsets_malevolent = [s for s in subsets_malevolent if len(s) == subset_size]

    return subsets_normal, subsets_malevolent