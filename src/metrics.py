import numpy as np
import matplotlib.pyplot as plt

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

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0.0

    return {
        'TP': TP, 'TN': TN, 'FP': FP, 'FN': FN,
        'Precision': round(precision, 4),
        'Recall': round(recall, 4),
        'Accuracy': round(accuracy, 4)
    }

def plot_custom_multiclass_matrix(features_list, predicted_labels, title="One-vs-All Detection Matrix"):
    """
    Genera una matrice Nx2 usando SOLO Matplotlib.
    Mappa ogni specifica classe di attacco contro la previsione binaria dell'NTC.
    """
    # 1. Raccogliamo i conteggi per ogni categoria originale
    results = {}
    for feat, pred in zip(features_list, predicted_labels):
        orig = feat['original_type']
        if orig not in results:
            results[orig] = {'Benevolent': 0, 'Malevolent': 0}
        results[orig][pred] += 1

    # Ordiniamo le categorie alfabeticamente
    categories = sorted(list(results.keys()))

    # 2. Costruiamo la matrice Numpy (N righe x 2 colonne)
    matrix = np.zeros((len(categories), 2), dtype=int)
    for i, cat in enumerate(categories):
        matrix[i, 0] = results[cat]['Benevolent']
        matrix[i, 1] = results[cat]['Malevolent']

    # 3. Disegniamo la Heatmap con Matplotlib
    fig, ax = plt.subplots(figsize=(8, 7))
    cax = ax.imshow(matrix, interpolation='nearest', cmap='Blues')

    # Configurazione Assi
    ax.set_xticks([0, 1])
    ax.set_xticklabels(['Predicted\nBenevolent', 'Predicted\nMalevolent'], fontsize=11, fontweight='bold')
    ax.set_yticks(np.arange(len(categories)))
    ax.set_yticklabels(categories, fontsize=11, fontweight='bold')

    ax.set_title(title, fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel('True Original Category', fontsize=12, fontweight='bold')

    # Aggiungiamo i numeri dentro ogni cella
    thresh = matrix.max() / 2.
    for i in range(len(categories)):
        for j in range(2):
            ax.text(j, i, format(matrix[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if matrix[i, j] > thresh else "black",
                    fontsize=12, fontweight='bold')

    fig.tight_layout()
    plt.show()

def calculate_multiclass_metrics(features_list, predicted_labels):
    """Calcola la Recall e i falsi negativi testuali per ogni singola categoria di attacco."""
    # (Mantieni qui il codice originale che avevamo fatto per la stampa testuale)
    # ... [Ometto per brevità, tieni quello che c'era] ...
    pass