def calculate_metrics(true_labels, predicted_labels):
    TP = TN = FP = FN = 0

    for true, pred in zip(true_labels, predicted_labels):
        if true == "Malevolent" and pred == "Malevolent":
            TP += 1
        elif true == "Benevolent" and pred == "Benevolent":
            TN += 1
        elif true == "Benevolent" and pred == "Malevolent":
            FP += 1
        elif true == "Malevolent" and pred == "Benevolent":
            FN += 1

    # Gestione delle divisioni per zero
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0.0

    return {
        'TP': TP, 'TN': TN, 'FP': FP, 'FN': FN,
        'Precision': round(precision, 4),
        'Recall': round(recall, 4),
        'Accuracy': round(accuracy, 4)
    }


def calculate_multiclass_metrics(features_list, predicted_labels):
    """Calcola la Recall e i falsi negativi per ogni singola categoria di attacco."""
    results = {}

    for feat, pred in zip(features_list, predicted_labels):
        orig_type = feat['original_type']
        true_label = feat['true_label']

        if orig_type not in results:
            results[orig_type] = {'TP': 0, 'TN': 0, 'FP': 0, 'FN': 0, 'Total': 0}

        results[orig_type]['Total'] += 1

        # Logica della matrice di confusione
        if true_label == "Malevolent" and pred == "Malevolent":
            results[orig_type]['TP'] += 1
        elif true_label == "Benevolent" and pred == "Benevolent":
            results[orig_type]['TN'] += 1
        elif true_label == "Benevolent" and pred == "Malevolent":
            results[orig_type]['FP'] += 1
        elif true_label == "Malevolent" and pred == "Benevolent":
            results[orig_type]['FN'] += 1

    print(f"\n{'-' * 65}")
    print(f"{'Categoria Attacco':<20} | {'Subset':<6} | {'Recall (Catturati)':<20} | {'Miss (FN)':<10}")
    print(f"{'-' * 65}")

    for attack, counts in sorted(results.items()):
        TP = counts['TP']
        FN = counts['FN']
        FP = counts['FP']
        total = counts['Total']

        if attack in ['Benevolent', 'Normal', 'normal']:
            # Per il traffico normale, stampiamo i Falsi Positivi
            fp_rate = FP / total if total > 0 else 0
            print(f"{attack:<20} | {total:<6} | False Positives: {FP:<5} | FP Rate: {fp_rate:.1%}")
        else:
            # Per gli attacchi, stampiamo la Recall (Sensibilità)
            recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
            print(f"{attack:<20} | {total:<6} | {recall:.4f} (TP:{TP:<3} FN:{FN:<3}) | F.Neg: {FN:<3}")
    print(f"{'-' * 65}\n")