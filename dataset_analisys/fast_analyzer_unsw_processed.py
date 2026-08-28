import pandas as pd

for file in ["../data/UNSW_NB15_training-set.csv", "../data/UNSW_NB15_testing-set.csv"]:
    try:
        df = pd.read_csv(file, low_memory=False)
        normali = len(df[df['attack_cat'].isin(['Normal', 'normal']) | df['attack_cat'].isna()])
        attacchi = len(df) - normali
        print(f"File: {file}")
        print(f"Totale: {len(df)} | Normali: {normali} | Attacchi: {attacchi}\n")
    except Exception as e:
        print(f"Errore con {file}: {e}")