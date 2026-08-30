import pandas as pd
import os

def update_type_column():
    dataset_dir = r"c:\Users\kadam\Downloads\icds-h\backend\dataset"
    out_path = os.path.join(dataset_dir, "unified_dataset.csv")
    
    print(f"Loading {out_path}...")
    df = pd.read_csv(out_path)
    
    # Fill `type` column for PhiUSIIL
    phi_mask = df['dataset_source'] == 'PhiUSIIL'
    df.loc[phi_mask & (df['label'] == 0), 'type'] = 'Normal'
    df.loc[phi_mask & (df['label'] == 1), 'type'] = 'Phishing'
    
    # Fill `type` column for CERT
    # Assuming label in CERT might be 'activity' or 'label'? Let's check what label CERT uses.
    cert_mask = df['dataset_source'] == 'CERT'
    df.loc[cert_mask & (df['label'] == 0), 'type'] = 'Normal'
    df.loc[cert_mask & (df['label'] == 1), 'type'] = 'Insider Threat'
    
    # Fix TON_IoT capitalization for output validation
    # user expects "DDoS", "Ransomware", "Normal"
    ton_mask = df['dataset_source'] == 'TON_IoT'
    df.loc[ton_mask & (df['type'] == 'ddos'), 'type'] = 'DDoS'
    df.loc[ton_mask & (df['type'] == 'ransomware'), 'type'] = 'Ransomware'
    df.loc[ton_mask & (df['type'] == 'normal'), 'type'] = 'Normal'
    
    print(f"Saving to {out_path}...")
    df.to_csv(out_path, index=False)
    print("Saved unified dataset.")
    
    # Validation
    print("\n--- Validation ---")
    print(df.groupby(['dataset_source', 'type']).size())
    print("\nUnique types in dataset:")
    print(df['type'].unique())
    print("Done.")

if __name__ == "__main__":
    update_type_column()
