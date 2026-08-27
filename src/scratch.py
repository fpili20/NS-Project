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
# 2. Suddivisione in Subset e calcolo statistico sul protocollo TCP
subset_size = 1000  # Suddividiamo il traffico in blocchi da 1000 pacchetti

# Creiamo due dataframe separati per traffico benevolo e malevolo
df_benevolent = clean_df[clean_df['type'] == 'Benevolent']
df_malevolent = clean_df[clean_df['type'] == 'Malevolent']

# Generiamo una lista di sottoinsiemi (subset) per ciascuna categoria
subsets_normal = [df_benevolent[i:i + subset_size] for i in range(0, len(df_benevolent), subset_size)]
subsets_malevolent = [df_malevolent[i:i + subset_size] for i in range(0, len(df_malevolent), subset_size)]

percent_tcp_normal = []
percent_tcp_malevolent = []

# Calcoliamo la percentuale di pacchetti TCP per i subset Benevoli
for subset in subsets_normal:
    total_pkts = len(subset)
    if total_pkts > 0:
        tcp_pkts = len(subset[subset['proto'] == 'tcp'])
        percent_tcp_normal.append(tcp_pkts / total_pkts)

# Calcoliamo la percentuale di pacchetti TCP per i subset Malevoli
for subset in subsets_malevolent:
    total_pkts = len(subset)
    if total_pkts > 0:
        tcp_pkts = len(subset[subset['proto'] == 'tcp'])
        percent_tcp_malevolent.append(tcp_pkts / total_pkts)


# 3. Funzione di Plotting per visualizzare la differenza tra le due classi
def plot_proto_percentages(subset_numbers_n, percent_normal, subset_numbers_m, percent_malevolent, proto):
    plt.figure(figsize=(10, 6))

    # Plottiamo le percentuali. Usiamo colori e marker diversi per distinguerli.
    plt.plot(subset_numbers_n, percent_normal, label='Benevolent', marker='o', linestyle='none', color='blue')
    plt.plot(subset_numbers_m, percent_malevolent, label='Malevolent', marker='x', color='red', linestyle='none')

    plt.xlabel('Subset Number')
    plt.ylabel(f'Percentage of {proto}')
    plt.title(f'Percentage of {proto} in "proto" for each class in subset')

    plt.legend()
    # Impostiamo il limite dell'asse Y tra 0 e 1 (rappresentando percentuali da 0% a 100%)
    plt.ylim(0, 1.1)
    plt.grid(True)
    plt.show()


# Richiamiamo la funzione per mostrare il grafico (necessario aver estratto prima i dati)
# Commentato per evitare blocchi dell'esecuzione se non c'è output visivo.
# plot_proto_percentages(range(len(percent_tcp_normal)), percent_tcp_normal,
#                        range(len(percent_tcp_malevolent)), percent_tcp_malevolent, 'tcp')


# ==========================================
# STEP 3: Development of an NTC
# ==========================================

# Definizione della Soglia (Threshold)
# Basandoci sull'osservazione visiva e statistica (grafici), supponiamo di aver notato
# che il traffico malevolo ha una densità di TCP molto alta, ad esempio superiore al 70%.
TCP_THRESHOLD = 0.70


def simple_ntc(subset, threshold):
    """
    Questo è il nostro Classificatore a Soglia Semplice.
    Valuta un sottoinsieme di pacchetti e stima la classe di traffico (NTC).
    """
    total_pkts = len(subset)
    if total_pkts == 0:
        return "Unknown"

    # Conta i pacchetti TCP
    tcp_pkts = len(subset[subset['proto'] == 'tcp'])
    tcp_percent = tcp_pkts / total_pkts

    # Classificazione basata su soglia: se la % di TCP supera la soglia, è etichettato come Malevolo
    if tcp_percent > threshold:
        return "Malevolent"
    else:
        return "Benevolent"


# Validazione dell'NTC: Testiamo il classificatore sul primissimo subset malevolo a disposizione
if len(subsets_malevolent) > 0:
    test_subset = subsets_malevolent[0]
    estimated_class = simple_ntc(test_subset, TCP_THRESHOLD)
    print(f"\nIl classificatore NTC ha valutato il subset di test come: {estimated_class}")