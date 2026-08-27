import pandas as pd
import os

# Opzione 1: Percorso relativo (più semplice)
# ".." significa "torna indietro di una cartella" (esce da src e va in NS-Project)
# "/data/" ti fa entrare nella cartella dei dati
file_path = r"../data/Train_Test_Network.csv"

# 1. Importazione del dataset e creazione del DataFrame
try:
    traffic_df = pd.read_csv(file_path)

    # 2. Ordinamento delle colonne in ordine alfabetico
    traffic_df = traffic_df.sort_index(axis=1)

    print(f"Dataset caricato con successo! Dimensioni: {traffic_df.shape}")
    print("\nColonne disponibili nel dataset:\n", traffic_df.columns.tolist())

except FileNotFoundError:
    print(f"ERRORE: Impossibile trovare il file al percorso '{file_path}'.")
    print("Assicurati di aver spostato il file CSV dentro la cartella 'data' e che il nome non abbia spazi extra!")


#MESCOLARE LE RIGHE E' IMPORTANTE PER EVITARE PATTERN SEQUENZIALI NASCOSTI
traffic_df = traffic_df.sample(frac=1).reset_index(drop=True)

# Isolamento dei campi di interesse
# Creiamo un DataFrame più pulito contenente solo i campi utili alla classificazione:
# 'proto' (protocollo), 'type' (tipo di attacco/normale) e 'label' (0 normale, 1 malevolo).
clean_df = traffic_df[["proto", "type", "label"]]
feature = 'type'
# Analizziamo la distribuzione dei tipi originali nel dataset
analysis_df = clean_df[feature]
val_count = analysis_df.value_counts().sort_index()
print("\nConteggio dei tipi di traffico prima del raggruppamento:\n", val_count)
numero_righe = clean_df.shape[0]
print(f"Metodo 1 - Il DataFrame clean_df contiene: {numero_righe} righe.")
# Try to extract some statistics
type_proto_counts = clean_df.groupby('type')['proto'].value_counts().unstack(fill_value=0)
print(type_proto_counts)

#Data analisys

# 1. Raggruppamento in macro-classi (Benevolent vs Malevolent)
# Mappiamo i vari tipi di attacchi specifici in una singola categoria 'Malevolent',
# e il traffico 'normal' in 'Benevolent'.
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

# Applichiamo la mappatura sovrascrivendo la colonna 'type'
clean_df['type'] = clean_df['type'].replace(category_mapping)
