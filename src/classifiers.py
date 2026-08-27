def evaluate_rule(val, rule):
    """
    Motore logico adattivo.
    Applica dinamicamente '>' o '<' in base a quanto appreso dall'optimizer.
    """
    if rule['direction'] == 'greater':
        return val > rule['threshold']
    else:
        return val < rule['threshold']


def classify_tcp(features, rule):
    return "Malevolent" if evaluate_rule(features['tcp'], rule) else "Benevolent"


def classify_udp(features, rule):
    return "Malevolent" if evaluate_rule(features['udp'], rule) else "Benevolent"


def classify_icmp(features, rule):
    return "Malevolent" if evaluate_rule(features['icmp'], rule) else "Benevolent"


def classify_multi(features, rules):
    """
    Classificatore combinato NTC (Multi-Soglia).
    Valuta simultaneamente i 3 protocolli applicando le regole adattive.
    """
    is_mal_tcp = evaluate_rule(features['tcp'], rules['tcp'])
    is_mal_udp = evaluate_rule(features['udp'], rules['udp'])
    is_mal_icmp = evaluate_rule(features['icmp'], rules['icmp'])

    # Logica OR: se anche un solo protocollo mostra un'anomalia, il blocco è malevolo
    if is_mal_tcp or is_mal_udp or is_mal_icmp:
        return "Malevolent"

    return "Benevolent"