import config
from data_loader import load_and_preprocess

def main():
    # 1 & 2. Caricamento Dati, Pulizia e Shuffling (eseguiti in data_loader)
    df = load_and_preprocess(config.FILE_PATH)
    if df is None:
        return
        
    # Mantieni esclusivamente le due colonne: protocollo ed etichetta originale (specifica tipologia)
    # NB: Conserviamo anche 'type' (macro-categoria Benevolent/Malevolent generata dal loader)
    #     in quanto necessaria per aggregare i TP/TN/FP/FN.
    
    # 3. Segmentazione in Subset (blocchi da esattamente 500 pacchetti)
    subset_size = 500
    num_subsets = len(df) // subset_size
    df_trunc = df.iloc[:num_subsets * subset_size]

    agg_benign = {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}
    agg_malicious = {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0}

    # 4. Confronto e Matrici di Confusione Locali
    for i in range(num_subsets):
        subset = df_trunc.iloc[i * subset_size : (i + 1) * subset_size]
        
        # Etichetta globale basata sulla classificazione maggioritaria della macro-categoria
        global_label = subset['type'].mode()[0]
        actual_labels = subset['type']
        
        tp, tn, fp, fn = 0, 0, 0, 0
        if global_label == 'Malevolent':
            tp = (actual_labels == 'Malevolent').sum()
            fp = (actual_labels == 'Benevolent').sum()
            
            # Aggregazione
            agg_malicious['TP'] += tp
            agg_malicious['TN'] += tn
            agg_malicious['FP'] += fp
            agg_malicious['FN'] += fn
        else:
            tn = (actual_labels == 'Benevolent').sum()
            fn = (actual_labels == 'Malevolent').sum()
            
            # Aggregazione
            agg_benign['TP'] += tp
            agg_benign['TN'] += tn
            agg_benign['FP'] += fp
            agg_benign['FN'] += fn

    # 5 & 6. Aggregazione e Output Esclusivo
    print("\n=== MATRICE DI CONFUSIONE AGGREGATA: SUBSET BENEVOLI ===")
    print(f"True Positive (TP): {agg_benign['TP']}")
    print(f"True Negative (TN): {agg_benign['TN']}")
    print(f"False Positive (FP): {agg_benign['FP']}")
    print(f"False Negative (FN): {agg_benign['FN']}\n")

    print("=== MATRICE DI CONFUSIONE AGGREGATA: SUBSET MALEVOLI ===")
    print(f"True Positive (TP): {agg_malicious['TP']}")
    print(f"True Negative (TN): {agg_malicious['TN']}")
    print(f"False Positive (FP): {agg_malicious['FP']}")
    print(f"False Negative (FN): {agg_malicious['FN']}")

if __name__ == "__main__":
    main()