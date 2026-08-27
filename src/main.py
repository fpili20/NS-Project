import config
from data_loader import load_and_preprocess, create_subsets
from features import get_all_features, plot_proto_percentages
from optimizer import find_best_threshold
from classifiers import classify_tcp, classify_udp, classify_icmp, classify_multi
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

    # 5. Ottimizzazione Soglia Automatica e Generazione Grafici
    print("\n--- Avvio Ottimizzatore Analitico ---")

    optimal_tcp_thresh = find_best_threshold(all_features, true_labels, protocol='tcp', show_plot=True)
    optimal_udp_thresh = find_best_threshold(all_features, true_labels, protocol='udp', show_plot=True)
    optimal_icmp_thresh = find_best_threshold(all_features, true_labels, protocol='icmp', show_plot=True)

    # 6. Preparazione Soglie per Classificazione Multi-Soglia
    dynamic_thresholds = {
        'tcp': optimal_tcp_thresh,
        'udp': optimal_udp_thresh,
        'icmp': optimal_icmp_thresh
    }

    # 7. Classificazione e Valutazione
    print("\n--- Fase di Classificazione e Valutazione ---")

    preds_tcp = []
    preds_udp = []
    preds_icmp = []
    preds_multi = []

    # Il processo alle intenzioni: i classificatori valutano ogni subset
    for feat in all_features:
        preds_tcp.append(classify_tcp(feat, dynamic_thresholds['tcp']))
        preds_udp.append(classify_udp(feat, dynamic_thresholds['udp']))
        preds_icmp.append(classify_icmp(feat, dynamic_thresholds['icmp']))
        preds_multi.append(classify_multi(feat, dynamic_thresholds))

    # 8. Stampa a confronto le metriche
    print("\n[Risultati Classificatore Singolo - Solo TCP]")
    print(calculate_metrics(true_labels, preds_tcp))

    print("\n[Risultati Classificatore Singolo - Solo UDP]")
    print(calculate_metrics(true_labels, preds_udp))

    print("\n[Risultati Classificatore Singolo - Solo ICMP]")
    print(calculate_metrics(true_labels, preds_icmp))

    print("\n[Risultati Classificatore Combinato - MULTI-SOGLIA]")
    print(calculate_metrics(true_labels, preds_multi))


if __name__ == "__main__":
    main()