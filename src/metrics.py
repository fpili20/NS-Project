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