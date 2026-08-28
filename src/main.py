import pandas as pd
import config
from data_loader import load_and_preprocess

def main():
    # 1 & 2. Caricamento Dati, Pulizia e Shuffling (eseguiti in data_loader)
    df = load_and_preprocess(config.FILE_PATH)
    if df is None:
        return
        
    # 3. Segmentazione in Subset (blocchi da esattamente 500 pacchetti)
    subset_size = 500
    num_subsets = len(df) // subset_size
    df_trunc = df.iloc[:num_subsets * subset_size]

    # Otteniamo tutti i tipi originali in ordine alfabetico per le colonne della matrice
    unique_types = sorted(df['original_type'].unique())
    
    # Inizializziamo i DataFrame per le matrici espanse (Tutti zeri)
    matrix_benign = pd.DataFrame(0, index=['TP', 'TN', 'FP', 'FN'], columns=unique_types)
    matrix_malicious = pd.DataFrame(0, index=['TP', 'TN', 'FP', 'FN'], columns=unique_types)

    # 4. Confronto e Matrici di Confusione Locali (con dettaglio espanso)
    for i in range(num_subsets):
        subset = df_trunc.iloc[i * subset_size : (i + 1) * subset_size]
        
        # Etichetta globale basata sulla classificazione maggioritaria della macro-categoria
        global_label = subset['type'].mode()[0]
        
        # Calcoliamo i conteggi per ogni tipologia di traffico all'interno di questo specifico subset
        type_counts = subset['original_type'].value_counts()
        
        for orig_type, count in type_counts.items():
            # Determiniamo la macro-categoria a cui appartiene questo specifico pacchetto
            macro_class = subset[subset['original_type'] == orig_type]['type'].iloc[0]
            
            if global_label == 'Malevolent':
                # Subset classificato come Malevolent -> tutte le predizioni per il blocco sono "Malevolent"
                if macro_class == 'Malevolent':
                    matrix_malicious.at['TP', orig_type] += count
                else:
                    matrix_malicious.at['FP', orig_type] += count
            else:
                # Subset classificato come Benevolent -> tutte le predizioni per il blocco sono "Benevolent"
                if macro_class == 'Malevolent':
                    matrix_benign.at['FN', orig_type] += count
                else:
                    matrix_benign.at['TN', orig_type] += count

    # 5 & 6. Aggregazione e Output Esclusivo
    print("\n=== MATRICE DI CONFUSIONE ESPANSA: SUBSET BENEVOLI ===")
    print(matrix_benign.to_string())

    print("\n=== MATRICE DI CONFUSIONE ESPANSA: SUBSET MALEVOLI ===")
    print(matrix_malicious.to_string())

if __name__ == "__main__":
    main()