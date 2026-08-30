import pandas as pd
import os

def combine_datasets():
    dataset_dir = r"c:\Users\kadam\Downloads\icds-h\backend\dataset"
    
    # 1. TON_IoT
    ton_path = os.path.join(dataset_dir, "ton_iot", "train_test_network.csv")
    print(f"Loading {ton_path}...")
    ton_df = pd.read_csv(ton_path)
    # Filter to only the classes we care about to save space
    ton_df = ton_df[ton_df['type'].isin(['normal', 'ddos', 'ransomware'])].copy()
    ton_df['dataset_source'] = 'TON_IoT'
    
    # 2. PhiUSIIL
    phi_path = os.path.join(dataset_dir, "phishing", "PhiUSIIL_Phishing_URL_Dataset.csv")
    print(f"Loading {phi_path}...")
    phi_df = pd.read_csv(phi_path)
    phi_df['dataset_source'] = 'PhiUSIIL'
    
    # 3. CERT
    cert_path = os.path.join(dataset_dir, "processed_cert.csv")
    print(f"Loading {cert_path}...")
    cert_df = pd.read_csv(cert_path)
    cert_df['dataset_source'] = 'CERT'
    
    # Combine
    print("Combining datasets...")
    unified_df = pd.concat([ton_df, phi_df, cert_df], ignore_index=True)
    
    # Save
    out_path = os.path.join(dataset_dir, "unified_dataset.csv")
    print(f"Saving to {out_path}...")
    unified_df.to_csv(out_path, index=False)
    print("Saved unified dataset.")
    
    # Remove old processed_cert.csv as requested
    print(f"Removing {cert_path}...")
    os.remove(cert_path)
    print("Done.")

if __name__ == "__main__":
    combine_datasets()
