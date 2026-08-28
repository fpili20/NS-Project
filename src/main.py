import pandas as pd
import config
from data_loader import load_and_preprocess

def main():
    # 1. Caricamento Dati
    df = load_and_preprocess(config.FILE_PATH)
    if df is None:
        return
        
    # 2. Segmentazione in Subset (Traffico MISTO ETEROGENEO, senza separazione artificiale)
    subset_size = 500
    num_subsets = len(df) // subset_size
    df_trunc = df.iloc[:num_subsets * subset_size]

    # Otteniamo tutti i tipi originali per le colonne della matrice
    unique_types = sorted(df['original_type'].unique())
    
    # Inizializziamo i DataFrame
    matrix_benign = pd.DataFrame(0, index=['TP', 'TN', 'FP', 'FN'], columns=unique_types)
    matrix_malicious = pd.DataFrame(0, index=['TP', 'TN', 'FP', 'FN'], columns=unique_types)

    # 3. Analisi Subset Eterogenei (Finestre Temporali)
    for i in range(num_subsets):
        subset = df_trunc.iloc[i * subset_size : (i + 1) * subset_size]
        
        # L'etichetta globale del subset eterogeneo è decisa a maggioranza
        global_label = subset['type'].mode()[0]
        
        type_counts = subset['original_type'].value_counts()
        
        for orig_type, count in type_counts.items():
            macro_class = subset[subset['original_type'] == orig_type]['type'].iloc[0]
            
            if global_label == 'Malevolent':
                if macro_class == 'Malevolent':
                    matrix_malicious.at['TP', orig_type] += count
                else:
                    matrix_malicious.at['FP', orig_type] += count
            else:
                if macro_class == 'Malevolent':
                    matrix_benign.at['FN', orig_type] += count
                else:
                    matrix_benign.at['TN', orig_type] += count

    # 4. Output
    print("\n=== MATRICE DI CONFUSIONE ESPANSA: SUBSET BENEVOLI ===")
    print(matrix_benign.to_string())

    print("\n=== MATRICE DI CONFUSIONE ESPANSA: SUBSET MALEVOLI ===")
    print(matrix_malicious.to_string())

if __name__ == "__main__":
    main()