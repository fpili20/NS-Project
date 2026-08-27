import matplotlib.pyplot as plt


def extract_protocol_percentages(subset):
    """Estrae le percentuali di TCP, UDP e ICMP da un singolo subset"""
    total_pkts = len(subset)
    if total_pkts == 0:
        return {'tcp': 0.0, 'udp': 0.0, 'icmp': 0.0}

    tcp_pkts = len(subset[subset['proto'] == 'tcp'])
    udp_pkts = len(subset[subset['proto'] == 'udp'])
    icmp_pkts = len(subset[subset['proto'] == 'icmp'])

    return {
        'tcp': tcp_pkts / total_pkts,
        'udp': udp_pkts / total_pkts,
        'icmp': icmp_pkts / total_pkts
    }


def get_all_features(subsets):
    """Applica l'estrazione a una lista di subset"""
    return [extract_protocol_percentages(s) for s in subsets]


def plot_proto_percentages(percent_normal, percent_malevolent, proto):
    """Plotta la percentuale di un dato protocollo per le due classi"""
    plt.figure(figsize=(10, 6))

    plt.plot(range(len(percent_normal)), percent_normal, label='Benevolent', marker='o', linestyle='none', color='blue')
    plt.plot(range(len(percent_malevolent)), percent_malevolent, label='Malevolent', marker='x', color='red',
             linestyle='none')

    plt.xlabel('Subset Number')
    plt.ylabel(f'Percentage of {proto.upper()}')
    plt.title(f'Percentage of {proto.upper()} in subsets')

    plt.legend()
    plt.ylim(0, 1.1)
    plt.grid(True)
    plt.show()