import numpy as np
import matplotlib.pyplot as plt


def plot_gaussian_intersection(benign_vals, malicious_vals, mu_b, sig_b, mu_m, sig_m, optimal_threshold, protocol):
    """Genera e mostra a schermo il grafico dell'intersezione gaussiana (senza salvare file)"""
    plt.figure(figsize=(10, 6))

    # Istogrammi dei dati reali
    plt.hist(benign_vals, bins=30, density=True, alpha=0.4, color='blue', label='Actual Benevolent Data')
    plt.hist(malicious_vals, bins=30, density=True, alpha=0.4, color='red', label='Actual Malevolent Data')

    # Curve Gaussiane teoriche
    xmin, xmax = plt.xlim()
    x = np.linspace(xmin, xmax, 100)
    p_benign = (1 / (sig_b * np.sqrt(2 * np.pi))) * np.exp(-((x - mu_b) ** 2) / (2 * sig_b ** 2))
    p_malicious = (1 / (sig_m * np.sqrt(2 * np.pi))) * np.exp(-((x - mu_m) ** 2) / (2 * sig_m ** 2))

    plt.plot(x, p_benign, color='darkblue', linewidth=2, label=f'Gaussian Benevolent ($\mu$={mu_b:.2f})')
    plt.plot(x, p_malicious, color='darkred', linewidth=2, label=f'Gaussian Malevolent ($\mu$={mu_m:.2f})')

    # Linea della Soglia Ottimale
    plt.axvline(optimal_threshold, color='green', linestyle='--', linewidth=2.5,
                label=f'Optimal Threshold: {optimal_threshold:.4f}')

    plt.title(f'Gaussian Intersection and Decision Boundary for {protocol.upper()}', fontsize=14, fontweight='bold')
    plt.xlabel(f'Percentage of {protocol.upper()} Packets in Subset', fontsize=12)
    plt.ylabel('Density', fontsize=12)
    plt.legend(loc='upper right')
    plt.grid(True, alpha=0.3)

    # Mostra semplicemente a schermo senza sporcare il disco
    plt.show()


def find_best_threshold(features_list, true_labels, protocol='tcp', show_plot=False):
    """
    Calcola la soglia ottimale e impara dinamicamente la direzione dell'anomalia.
    Restituisce un dizionario con soglia e regola di direzione.
    """
    benign_vals = [f[protocol] for f, label in zip(features_list, true_labels) if label == 'Benevolent']
    malicious_vals = [f[protocol] for f, label in zip(features_list, true_labels) if label == 'Malevolent']

    # Sicurezza nel caso in cui manchi una classe
    if len(benign_vals) == 0 or len(malicious_vals) == 0:
        return {'threshold': 0.50, 'direction': 'greater'}

    mu_b = np.mean(benign_vals)
    sig_b = np.std(benign_vals) + 1e-9

    mu_m = np.mean(malicious_vals)
    sig_m = np.std(malicious_vals) + 1e-9

    # 1. Calcolo Analitico della Soglia tramite Intersezione Gaussiana Ponderata
    optimal_threshold = (mu_b * sig_m + mu_m * sig_b) / (sig_b + sig_m)

    # 2. INTELLIGENZA ADATTIVA: Inferenza della direzione dell'attacco
    direction = 'greater' if mu_m > mu_b else 'less'

    print(f"\n[Optimizer] Statistical Analysis for {protocol.upper()}:")
    print(f"  - Benevolent: Mean = {mu_b:.4f}, Std = {sig_b:.4f}")
    print(f"  - Malevolent: Mean = {mu_m:.4f}, Std = {sig_m:.4f}")
    print(f"  -> Calculated Optimal Threshold: {optimal_threshold:.4f} (Rule: {direction})")

    if show_plot:
        plot_gaussian_intersection(benign_vals, malicious_vals, mu_b, sig_b, mu_m, sig_m, optimal_threshold, protocol)

    return {
        'threshold': round(optimal_threshold, 4),
        'direction': direction
    }