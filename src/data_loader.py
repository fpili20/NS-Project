import pandas as pd
from config import CATEGORY_MAPPING, SUBSET_SIZE


def load_and_preprocess(file_path):
    try:
        traffic_df = pd.read_csv(file_path)
        traffic_df = traffic_df.sort_index(axis=1)

        print(f"[Data Loader] Dataset caricato! Dimensioni: {traffic_df.shape}")

        # Shuffling per evitare pattern sequenziali
        traffic_df = traffic_df.sample(frac=1, random_state=42).reset_index(drop=True)

        # Isoliamo i campi utili
        clean_df = traffic_df[["proto", "type", "label"]].copy()

        # Mappatura in macro-classi
        clean_df['type'] = clean_df['type'].replace(CATEGORY_MAPPING)

        return clean_df

    except FileNotFoundError:
        print(f"[ERRORE] Impossibile trovare il file: '{file_path}'.")
        return None


def create_subsets(df, subset_size=SUBSET_SIZE):
    # Separiamo in base alla classe
    df_benevolent = df[df['type'] == 'Benevolent']
    df_malevolent = df[df['type'] == 'Malevolent']

    # Creiamo i subset
    subsets_normal = [df_benevolent[i:i + subset_size] for i in range(0, len(df_benevolent), subset_size)]
    subsets_malevolent = [df_malevolent[i:i + subset_size] for i in range(0, len(df_malevolent), subset_size)]

    # Rimuoviamo eventuali subset troppo piccoli alla fine (opzionale ma consigliato per coerenza statistica)
    subsets_normal = [s for s in subsets_normal if len(s) == subset_size]
    subsets_malevolent = [s for s in subsets_malevolent if len(s) == subset_size]

    return subsets_normal, subsets_malevolent