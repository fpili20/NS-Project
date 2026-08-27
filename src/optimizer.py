import numpy as np
import matplotlib.pyplot as plt


def plot_gaussian_intersection(benign_vals, malicious_vals, mu_b, sig_b, mu_m, sig_m, threshold, protocol):
    """
    Generates a plot showing the actual data distribution, the theoretical
    Gaussian curves, and the optimal decision boundary (threshold).
    Saves the plot as a high-resolution PNG for the final report.
    """
    plt.figure(figsize=(10, 6))

    # 1. Plot the actual data histograms (Density=True normalizes the scale)
    plt.hist(benign_vals, bins=30, alpha=0.4, density=True, color='blue', label='Actual Benevolent Data')
    plt.hist(malicious_vals, bins=30, alpha=0.4, density=True, color='red', label='Actual Malevolent Data')

    # 2. Generate x-axis values from 0 to 1 (0% to 100%)
    x = np.linspace(0, 1, 1000)

    # 3. Calculate theoretical Gaussian PDF (Probability Density Function)
    pdf_b = (1 / (sig_b * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((x - mu_b) / sig_b) ** 2)
    pdf_m = (1 / (sig_m * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((x - mu_m) / sig_m) ** 2)

    # 4. Plot the theoretical bell curves
    plt.plot(x, pdf_b, color='darkblue', linewidth=2, label=f'Gaussian Benevolent ($\mu$={mu_b:.2f})')
    plt.plot(x, pdf_m, color='darkred', linewidth=2, label=f'Gaussian Malevolent ($\mu$={mu_m:.2f})')

    # 5. Plot the optimal threshold line
    plt.axvline(threshold, color='green', linestyle='dashed', linewidth=2.5,
                label=f'Optimal Threshold: {threshold:.4f}')

    # Formatting for the report
    plt.title(f'Gaussian Intersection and Decision Boundary for {protocol.upper()}', fontsize=14, fontweight='bold')
    plt.xlabel(f'Percentage of {protocol.upper()} Packets in Subset', fontsize=12)
    plt.ylabel('Density', fontsize=12)
    plt.legend(loc='upper right')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    # Display the plot
    plt.show()


def find_best_threshold(features_list, true_labels, protocol='tcp', show_plot=False):
    """
    Calculates the optimal threshold using the Variance-Weighted Gaussian Intersection.
    """
    benign_vals = [f[protocol] for f, label in zip(features_list, true_labels) if label == 'Benevolent']
    malicious_vals = [f[protocol] for f, label in zip(features_list, true_labels) if label == 'Malevolent']

    if len(benign_vals) == 0 or len(malicious_vals) == 0:
        return 0.50

    mu_b = np.mean(benign_vals)
    sig_b = np.std(benign_vals) + 1e-9

    mu_m = np.mean(malicious_vals)
    sig_m = np.std(malicious_vals) + 1e-9

    # Variance-Weighted Threshold Formula
    optimal_threshold = (mu_b * sig_m + mu_m * sig_b) / (sig_b + sig_m)

    print(f"\n[Optimizer] Statistical Analysis for {protocol.upper()}:")
    print(f"  - Benevolent: Mean = {mu_b:.4f}, Std = {sig_b:.4f}")
    print(f"  - Malevolent: Mean = {mu_m:.4f}, Std = {sig_m:.4f}")
    print(f"  -> Calculated Optimal Threshold: {optimal_threshold:.4f}")

    # Generate the plot if requested
    if show_plot:
        plot_gaussian_intersection(benign_vals, malicious_vals, mu_b, sig_b, mu_m, sig_m, optimal_threshold, protocol)

    return round(optimal_threshold, 4)