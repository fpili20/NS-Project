# Percorsi dei file
FILE_PATH = r"../data/Train_Test_Network.csv"

# Parametri di raggruppamento
SUBSET_SIZE = 1000

# Mappatura delle categorie (Benevolent vs Malevolent)
CATEGORY_MAPPING = {
    'normal': 'Benevolent',
    'backdoor': 'Malevolent',
    'ddos': 'Malevolent',
    'dos': 'Malevolent',
    'injection': 'Malevolent',
    'mitm': 'Malevolent',
    'password': 'Malevolent',
    'ransomware': 'Malevolent',
    'scanning': 'Malevolent',
    'xss': 'Malevolent'
}

# Soglie di default (verranno poi sovrascritte dall'optimizer)
DEFAULT_THRESHOLDS = {
    'tcp': 0.70,
    'udp': 0.20,
    'icmp': 0.10
}