import os
import sys
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_fscore_support
import joblib
import json

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CML_DIR = os.path.join(BASE_DIR, "cml")
DATASET_DIR = os.path.join(BASE_DIR, "dataset")

TON_IOT_PATH = os.path.join(DATASET_DIR, "ton_iot", "train_test_network.csv")
PHISHING_PATH = os.path.join(DATASET_DIR, "phishing", "PhiUSIIL_Phishing_URL_Dataset.csv")
CERT_LOGON_PATH = os.path.join(DATASET_DIR, "insider_threat", "logon.csv")
CERT_DEVICE_PATH = os.path.join(DATASET_DIR, "insider_threat", "device.csv")
CERT_INSIDERS_PATH = os.path.join(DATASET_DIR, "insider_threat", "answers", "insiders.csv")

def save_metrics(name, y_test, y_pred, classes):
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted')
    report = classification_report(y_test, y_pred, target_names=[str(c) for c in classes], output_dict=True)
    
    metrics_data = {
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "classification_report": report
    }
    
    out_path = os.path.join(CML_DIR, f"{name}_metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics_data, f, indent=4)
    print(f"[Metrics] Saved {name} evaluation results to {out_path}")
    print(f"Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")

def train_ton_iot():
    print("\n==========================================")
    print("Training TON_IoT Model (DDoS & Ransomware)")
    print("==========================================")
    
    if not os.path.exists(TON_IOT_PATH):
        print(f"Error: {TON_IOT_PATH} not found.")
        return
        
    print("Loading TON_IoT dataset...")
    # Load required columns
    cols = ['src_port', 'dst_port', 'proto', 'duration', 'src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts', 'type']
    df = pd.read_csv(TON_IOT_PATH, usecols=cols)
    
    # Filter to normal, ddos, ransomware
    df = df[df['type'].isin(['normal', 'ddos', 'ransomware'])].copy()
    print(f"Filtered shape: {df.shape}")
    print(df['type'].value_counts())
    
    # Preprocess duration, src_bytes, dst_bytes to numeric
    for col in ['duration', 'src_bytes', 'dst_bytes']:
        df[col] = pd.to_numeric(df[col].astype(str).str.replace('-', '0'), errors='coerce').fillna(0)
        
    # Map proto using dict
    proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
    df['proto_num'] = df['proto'].str.lower().map(proto_map).fillna(0).astype(int)
    
    features = ['src_port', 'dst_port', 'proto_num', 'duration', 'src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts']
    X = df[features].values
    y = df['type'].values
    
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)
    
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    print("Training MLP Classifier for TON_IoT...")
    model = MLPClassifier(hidden_layer_sizes=(64, 32), activation='relu', solver='adam', max_iter=200, random_state=42, early_stopping=True)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    save_metrics("ton_iot", y_test, y_pred, le.classes_)
    
    # Save objects
    joblib.dump(model, os.path.join(CML_DIR, "ton_iot_model.pkl"))
    joblib.dump(scaler, os.path.join(CML_DIR, "ton_iot_scaler.pkl"))
    joblib.dump(le, os.path.join(CML_DIR, "ton_iot_le.pkl"))
    print("TON_IoT training artifacts saved.")

def train_phishing():
    print("\n==========================================")
    print("Training PhiUSIIL Phishing Model")
    print("==========================================")
    
    if not os.path.exists(PHISHING_PATH):
        print(f"Error: {PHISHING_PATH} not found.")
        return
        
    print("Loading PhiUSIIL dataset...")
    df = pd.read_csv(PHISHING_PATH)
    print(f"Dataset shape: {df.shape}")
    print(df['label'].value_counts())
    
    features = [
        'URLLength', 'DomainLength', 'URLSimilarityIndex', 
        'CharContinuationRate', 'TLDLegitimateProb', 'NoOfSubDomain', 
        'LetterRatioInURL', 'DegitRatioInURL', 'SpacialCharRatioInURL', 'IsHTTPS'
    ]
    
    X = df[features].values
    y = df['label'].values  # 0 or 1
    
    # Subsample to keep training fast and prevent out-of-memory
    if len(df) > 50000:
        print("Subsampling Phishing dataset for faster training...")
        df_sub = df.sample(n=40000, random_state=42)
        X = df_sub[features].values
        y = df_sub['label'].values
        
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    print("Training MLP Classifier for Phishing...")
    model = MLPClassifier(hidden_layer_sizes=(64, 32), activation='relu', solver='adam', max_iter=200, random_state=42, early_stopping=True)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    save_metrics("phishing", y_test, y_pred, [0, 1])
    
    # Save objects
    joblib.dump(model, os.path.join(CML_DIR, "phishing_model.pkl"))
    joblib.dump(scaler, os.path.join(CML_DIR, "phishing_scaler.pkl"))
    print("Phishing training artifacts saved.")

def train_cert():
    print("\n==========================================")
    print("Training CERT Insider Threat Model")
    print("==========================================")

    if not (
        os.path.exists(CERT_LOGON_PATH)
        and os.path.exists(CERT_DEVICE_PATH)
        and os.path.exists(CERT_INSIDERS_PATH)
    ):
        print("Error: CERT dataset files missing in dataset/insider_threat/.")
        return

    print("Loading insiders list...")
    insiders = pd.read_csv(CERT_INSIDERS_PATH)
    insiders["start"] = pd.to_datetime(insiders["start"], errors="coerce")
    insiders["end"] = pd.to_datetime(insiders["end"], errors="coerce")
    insiders = insiders.dropna(subset=["start", "end"])

    print("Loading Logon logs...")
    logon = pd.read_csv(CERT_LOGON_PATH)
    logon["date"] = pd.to_datetime(logon["date"], format="mixed")

    print("Loading Device logs...")
    device = pd.read_csv(CERT_DEVICE_PATH)
    device["date"] = pd.to_datetime(device["date"], format="mixed")

    # Keep the columns required by the CERT feature pipeline
    logon_sub = logon[["date", "user", "pc", "activity"]].copy()
    device_sub = device[["date", "user", "pc", "activity"]].copy()

    combined = pd.concat([logon_sub, device_sub], ignore_index=True)
    combined = combined.sort_values(by="date").reset_index(drop=True)

    print(f"Combined CERT logon + device shape: {combined.shape}")

    # Label events using insider timelines
    print("Labeling events based on insiders timeline...")
    combined["label"] = 0

    malicious_users = set(insiders["user"].unique())

    for user in malicious_users:
        user_insiders = insiders[insiders["user"] == user]
        user_mask = combined["user"] == user

        if not user_mask.any():
            continue

        user_dates = combined.loc[user_mask, "date"]
        is_malicious = pd.Series(False, index=user_dates.index)

        for _, row in user_insiders.iterrows():
            is_malicious |= (
                (user_dates >= row["start"])
                & (user_dates <= row["end"])
            )

        combined.loc[user_dates[is_malicious].index, "label"] = 1

    print("Label distribution:")
    print(combined["label"].value_counts())

    # Feature extraction
    print("Extracting features...")

    combined["hour"] = combined["date"].dt.hour
    combined["dayofweek"] = combined["date"].dt.dayofweek
    combined["is_after_hours"] = (
        (combined["hour"] < 6) | (combined["hour"] > 19)
    ).astype(int)
    combined["is_weekend"] = (combined["dayofweek"] >= 5).astype(int)

    activity_map = {
        "Logon": 0,
        "Logoff": 1,
        "Connect": 2,
        "Disconnect": 3,
    }

    combined["activity_type"] = (
        combined["activity"]
        .map(activity_map)
        .fillna(0)
        .astype(int)
    )

    # Fit label encoders for users and PCs
    user_le = LabelEncoder()
    combined["user_enc"] = user_le.fit_transform(combined["user"])

    pc_le = LabelEncoder()
    combined["pc_enc"] = pc_le.fit_transform(combined["pc"])

    # These 7 features must exactly match dataset_engine.py and shap_explainer.py
    features = [
        "hour",
        "dayofweek",
        "is_after_hours",
        "is_weekend",
        "activity_type",
        "user_enc",
        "pc_enc",
    ]

    X = combined[features].values
    y = combined["label"].values

    # Balance 1:4 positive to negative
    pos_mask = y == 1
    neg_mask = y == 0

    n_pos = int(pos_mask.sum())
    print(f"Number of positive CERT events: {n_pos}")

    if n_pos == 0:
        print("Error: No positive CERT insider-threat events were found.")
        return

    n_neg_sample = min(int(neg_mask.sum()), n_pos * 4)

    # Reproducible sampling
    rng = np.random.RandomState(42)

    neg_indices = rng.choice(
        np.where(neg_mask)[0],
        size=n_neg_sample,
        replace=False,
    )

    pos_indices = np.where(pos_mask)[0]

    final_indices = np.concatenate([pos_indices, neg_indices])

    # Reproducible shuffle
    rng.shuffle(final_indices)

    X_bal = X[final_indices]
    y_bal = y[final_indices]

    print(f"Balanced training shape: {X_bal.shape}")
    print("Balanced label distribution:")
    print(pd.Series(y_bal).value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        X_bal,
        y_bal,
        test_size=0.2,
        random_state=42,
        stratify=y_bal,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("Training MLP Classifier for CERT...")

    model = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        solver="adam",
        max_iter=200,
        random_state=42,
        early_stopping=True,
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    save_metrics("cert", y_test, y_pred, [0, 1])

    # Save model artifacts
    joblib.dump(model, os.path.join(CML_DIR, "cert_model.pkl"))
    joblib.dump(scaler, os.path.join(CML_DIR, "cert_scaler.pkl"))
    joblib.dump(user_le, os.path.join(CML_DIR, "cert_user_le.pkl"))
    joblib.dump(pc_le, os.path.join(CML_DIR, "cert_pc_le.pkl"))

    print("CERT training artifacts saved.")

    # Save processed replay dataset
    threat_events = combined[combined["label"] == 1]

    normal_pool = combined[combined["label"] == 0]

    normal_events = normal_pool.sample(
        n=min(5000, len(normal_pool)),
        random_state=42,
    )

    processed_df = pd.concat(
        [threat_events, normal_events],
        ignore_index=True,
    )

    processed_df = (
        processed_df
        .sort_values(by="date")
        .reset_index(drop=True)
    )

    processed_df = processed_df[
        ["date", "user", "pc", "activity", "label"]
    ]

    processed_df.to_csv(
        os.path.join(DATASET_DIR, "processed_cert.csv"),
        index=False,
    )

    print(
        f"Saved {len(processed_df)} processed replay rows "
        f"to dataset/processed_cert.csv"
    )
if __name__ == "__main__":
     train_ton_iot()
     train_phishing()
     train_cert()
     print("\nAll models trained and preprocessors saved successfully!")