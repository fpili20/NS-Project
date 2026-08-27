import numpy as np
from classifiers import classify_tcp
from metrics import calculate_metrics


def find_best_threshold(features_list, true_labels, protocol='tcp'):
    best_threshold = 0.0
    best_accuracy = 0.0

    # Testiamo le soglie da 0.0 a 1.0 con incrementi di 0.05
    thresholds_to_test = np.arange(0.0, 1.05, 0.05)

    for thresh in thresholds_to_test:
        predictions = []
        for feat in features_list:
            # Semplice logica basata sul protocollo selezionato
            pred = "Malevolent" if feat[protocol] > thresh else "Benevolent"
            predictions.append(pred)

        metrics = calculate_metrics(true_labels, predictions)

        if metrics['Accuracy'] > best_accuracy:
            best_accuracy = metrics['Accuracy']
            best_threshold = thresh

    print(
        f"[Optimizer] Miglior soglia {protocol.upper()} trovata: {best_threshold:.2f} (Accuracy: {best_accuracy:.2f})")
    return round(best_threshold, 2)