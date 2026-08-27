import config
from data_loader import load_and_preprocess, create_subsets
from features import get_all_features, plot_proto_percentages
from optimizer import find_best_threshold
from classifiers import classify_tcp
from metrics import calculate_metrics


def main():
    print("=== AVVIO PROGETTO NETWORK SECURITY ===")

    # 1. Caricamento Dati
    df = load_and_preprocess(config.FILE_PATH)
    if df is None:
        return

    # 2. Creazione Subsets
    subsets_normal, subsets_malevolent = create_subsets(df, config.SUBSET_SIZE)
    print(f"Creati {len(subsets_normal)} subset Benevoli e {len(subsets_malevolent)} subset Malevoli.")

    # 3. Estrazione Features
    feat_normal = get_all_features(subsets_normal)
    feat_malevolent = get_all_features(subsets_malevolent)

    # (Opzionale) Plot delle features TCP
    tcp_normal = [f['tcp'] for f in feat_normal]
    tcp_malevolent = [f['tcp'] for f in feat_malevolent]
    # Scommenta la riga sotto per vedere il grafico
    # plot_proto_percentages(tcp_normal, tcp_malevolent, 'tcp')

    # 4. Creazione dataset di test combinato per l'ottimizzatore e le metriche
    all_features = feat_normal + feat_malevolent
    true_labels = ["Benevolent"] * len(feat_normal) + ["Malevolent"] * len(feat_malevolent)

    # 5. Ottimizzazione Soglia Automatica (senza guardare il grafico)
    print("\n--- Avvio Ottimizzatore ---")
    optimal_tcp_thresh = find_best_threshold(all_features, true_labels, protocol='tcp')

    # 6. Classificazione con la soglia ottimizzata
    print(f"\n--- Classificazione (Soglia TCP: {optimal_tcp_thresh}) ---")
    predictions = [classify_tcp(f, optimal_tcp_thresh) for f in all_features]

    # 7. Calcolo Metriche
    results = calculate_metrics(true_labels, predictions)
    print("\nRisultati della Classificazione:")
    for key, value in results.items():
        print(f"- {key}: {value}")


if __name__ == "__main__":
    main()