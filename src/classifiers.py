def classify_tcp(features, threshold):
    # Il TCP AUMENTA durante gli attacchi di questo dataset
    return "Malevolent" if features['tcp'] > threshold else "Benevolent"


def classify_udp(features, threshold):
    # L'UDP DIMINUISCE (viene diluito) durante gli attacchi TCP
    return "Malevolent" if features['udp'] < threshold else "Benevolent"


def classify_icmp(features, threshold):
    # L'ICMP DIMINUISCE (viene diluito) durante gli attacchi TCP
    return "Malevolent" if features['icmp'] < threshold else "Benevolent"


def classify_multi(features, thresholds):
    """
    Classificatore combinato NTC.
    Valuta simultaneamente le variazioni anomale dei 3 protocolli.
    Se anche un solo protocollo supera la sua soglia critica (in eccesso o in difetto),
    il blocco viene etichettato come anomalo (Malevolent).
    """
    is_mal_tcp = features['tcp'] > thresholds['tcp']
    is_mal_udp = features['udp'] < thresholds['udp']
    is_mal_icmp = features['icmp'] < thresholds['icmp']

    # Logica OR: Basta un'anomalia per far scattare l'allarme
    if is_mal_tcp or is_mal_udp or is_mal_icmp:
        return "Malevolent"

    return "Benevolent"