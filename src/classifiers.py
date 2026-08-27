def classify_tcp(features, threshold):
    return "Malevolent" if features['tcp'] > threshold else "Benevolent"


def classify_udp(features, threshold):
    return "Malevolent" if features['udp'] > threshold else "Benevolent"


def classify_icmp(features, threshold):
    return "Malevolent" if features['icmp'] > threshold else "Benevolent"


def classify_multi(features, thresholds):
    """
    Classificatore combinato. Esempio logico: se supera la soglia TCP
    OPPURE la soglia UDP, è malevolo. Puoi modificare la logica a tuo piacimento.
    """
    is_mal_tcp = features['tcp'] > thresholds['tcp']
    is_mal_udp = features['udp'] > thresholds['udp']
    is_mal_icmp = features['icmp'] > thresholds['icmp']

    if is_mal_tcp or is_mal_udp or is_mal_icmp:
        return "Malevolent"
    return "Benevolent"