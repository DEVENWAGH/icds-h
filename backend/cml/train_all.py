import os
import sys
import numpy as np
import pandas as pd
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_fscore_support, accuracy_score
from sklearn.ensemble import IsolationForest
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

TON_FEATURE_COLS = [
    "src_port", "dst_port", "proto_num",
    "duration", "src_bytes", "dst_bytes",
    "src_pkts", "dst_pkts",
]

PHI_FEATURE_COLS = [
    "URLLength", "DomainLength", "URLSimilarityIndex",
    "CharContinuationRate", "TLDLegitimateProb", "NoOfSubDomain",
    "LetterRatioInURL", "DegitRatioInURL", "SpacialCharRatioInURL",
    "IsHTTPS",
]

CERT_FEATURE_COLS = [
    "hour", "dayofweek", "is_after_hours",
    "is_weekend", "activity_type", "user_enc", "pc_enc",
]


def save_metrics(name, y_test, y_pred, classes):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average='weighted'
    )
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred,
        target_names=[str(c) for c in classes],
        output_dict=True,
    )

    metrics_data = {
        "accuracy": float(acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "classification_report": report,
    }

    out_path = os.path.join(CML_DIR, f"{name}_metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics_data, f, indent=4)
    print(f"[Metrics] Saved {name} evaluation results to {out_path}")
    print(f"Accuracy: {acc:.4f} | Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=[str(c) for c in classes]))


def train_ton_iot():
    print("\n" + "=" * 60)
    print("Training TON_IoT Model - ALL Attack Classes")
    print("=" * 60)

    if not os.path.exists(TON_IOT_PATH):
        print(f"Error: {TON_IOT_PATH} not found.")
        return

    print("Loading TON_IoT dataset...")
    cols = [
        "src_port", "dst_port", "proto", "duration",
        "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "type",
    ]
    df = pd.read_csv(TON_IOT_PATH, usecols=cols)

    print(f"Full dataset shape: {df.shape}")
    print("Class distribution:")
    print(df["type"].value_counts())

    df = df.dropna(subset=["type"]).copy()
    df["type"] = df["type"].astype(str).str.strip().str.lower()
    df = df[df["type"] != ""].copy()

    print(f"\nFiltered shape: {df.shape}")
    print(df["type"].value_counts())

    for col in ["duration", "src_bytes", "dst_bytes"]:
        df[col] = pd.to_numeric(
            df[col].astype(str).str.replace("-", "0"),
            errors="coerce",
        ).fillna(0)

    for col in ["src_port", "dst_port", "src_pkts", "dst_pkts"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    df["proto_num"] = (
        df["proto"].str.lower().map(proto_map).fillna(0).astype(int)
    )

    features = [
        "src_port", "dst_port", "proto_num",
        "duration", "src_bytes", "dst_bytes",
        "src_pkts", "dst_pkts",
    ]
    X = df[features].values
    y = df["type"].values

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    print(f"\nLabel encoder classes: {le.classes_}")
    print(f"Number of classes: {len(le.classes_)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=0.2, random_state=42, stratify=y_enc,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("Training MLP Classifier for TON_IoT (all classes)...")
    model = MLPClassifier(
        hidden_layer_sizes=(128, 64, 32),
        activation="relu",
        solver="adam",
        max_iter=300,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    save_metrics("ton_iot", y_test, y_pred, le.classes_)

    joblib.dump(model, os.path.join(CML_DIR, "ton_iot_model.pkl"))
    joblib.dump(scaler, os.path.join(CML_DIR, "ton_iot_scaler.pkl"))
    joblib.dump(le, os.path.join(CML_DIR, "ton_iot_le.pkl"))
    print("TON_IoT training artifacts saved.")

    normal_mask = y == "normal"
    if normal_mask.sum() > 0:
        bg_indices = np.where(normal_mask)[0][:50]
        bg_raw = X[bg_indices]
        bg_scaled = scaler.transform(bg_raw)
        joblib.dump(bg_scaled, os.path.join(CML_DIR, "shap_background_ton.pkl"))
        print(f"SHAP background saved: {len(bg_scaled)} TON_IoT samples")

    return df, scaler, features


def train_phishing():
    print("\n" + "=" * 60)
    print("Training PhiUSIIL Phishing Model")
    print("=" * 60)

    if not os.path.exists(PHISHING_PATH):
        print(f"Error: {PHISHING_PATH} not found.")
        return

    print("Loading PhiUSIIL dataset...")
    df = pd.read_csv(PHISHING_PATH)
    print(f"Dataset shape: {df.shape}")
    print(df["label"].value_counts())

    features = PHI_FEATURE_COLS
    X = df[features].values
    y = df["label"].values

    if len(df) > 50000:
        print("Subsampling Phishing dataset for faster training...")
        df_sub = df.sample(n=40000, random_state=42)
        X = df_sub[features].values
        y = df_sub["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("Training MLP Classifier for Phishing...")
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
    save_metrics("phishing", y_test, y_pred, [0, 1])

    joblib.dump(model, os.path.join(CML_DIR, "phishing_model.pkl"))
    joblib.dump(scaler, os.path.join(CML_DIR, "phishing_scaler.pkl"))
    print("Phishing training artifacts saved.")

    normal_mask = y == 0
    if normal_mask.sum() > 0:
        bg_indices = np.where(normal_mask)[0][:50]
        bg_raw = X[bg_indices]
        bg_scaled = scaler.transform(bg_raw)
        joblib.dump(bg_scaled, os.path.join(CML_DIR, "shap_background_phi.pkl"))
        print(f"SHAP background saved: {len(bg_scaled)} PhiUSIIL samples")

    return scaler


def train_cert():
    print("\n" + "=" * 60)
    print("Training CERT Insider Threat Model")
    print("=" * 60)

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

    logon_sub = logon[["date", "user", "pc", "activity"]].copy()
    device_sub = device[["date", "user", "pc", "activity"]].copy()

    combined = pd.concat([logon_sub, device_sub], ignore_index=True)
    combined = combined.sort_values(by="date").reset_index(drop=True)

    print(f"Combined CERT logon + device shape: {combined.shape}")

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

    print("Extracting features...")

    combined["hour"] = combined["date"].dt.hour
    combined["dayofweek"] = combined["date"].dt.dayofweek
    combined["is_after_hours"] = (
        (combined["hour"] < 6) | (combined["hour"] > 19)
    ).astype(int)
    combined["is_weekend"] = (combined["dayofweek"] >= 5).astype(int)

    activity_map = {"Logon": 0, "Logoff": 1, "Connect": 2, "Disconnect": 3}
    combined["activity_type"] = (
        combined["activity"].map(activity_map).fillna(0).astype(int)
    )

    user_le = LabelEncoder()
    combined["user_enc"] = user_le.fit_transform(combined["user"])

    pc_le = LabelEncoder()
    combined["pc_enc"] = pc_le.fit_transform(combined["pc"])

    features = CERT_FEATURE_COLS
    X = combined[features].values
    y = combined["label"].values

    pos_mask = y == 1
    neg_mask = y == 0
    n_pos = int(pos_mask.sum())
    print(f"Number of positive CERT events: {n_pos}")

    if n_pos == 0:
        print("Error: No positive CERT insider-threat events were found.")
        return

    n_neg_sample = min(int(neg_mask.sum()), n_pos * 4)
    rng = np.random.RandomState(42)
    neg_indices = rng.choice(np.where(neg_mask)[0], size=n_neg_sample, replace=False)
    pos_indices = np.where(pos_mask)[0]
    final_indices = np.concatenate([pos_indices, neg_indices])
    rng.shuffle(final_indices)

    X_bal = X[final_indices]
    y_bal = y[final_indices]

    print(f"Balanced training shape: {X_bal.shape}")
    print("Balanced label distribution:")
    print(pd.Series(y_bal).value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        X_bal, y_bal, test_size=0.2, random_state=42, stratify=y_bal,
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

    joblib.dump(model, os.path.join(CML_DIR, "cert_model.pkl"))
    joblib.dump(scaler, os.path.join(CML_DIR, "cert_scaler.pkl"))
    joblib.dump(user_le, os.path.join(CML_DIR, "cert_user_le.pkl"))
    joblib.dump(pc_le, os.path.join(CML_DIR, "cert_pc_le.pkl"))
    print("CERT training artifacts saved.")

    normal_mask_full = y == 0
    if normal_mask_full.sum() > 0:
        bg_indices = np.where(normal_mask_full)[0][:50]
        bg_raw = X[bg_indices]
        bg_scaled = scaler.transform(bg_raw)
        joblib.dump(bg_scaled, os.path.join(CML_DIR, "shap_background_cert.pkl"))
        print(f"SHAP background saved: {len(bg_scaled)} CERT samples")

    threat_events = combined[combined["label"] == 1]
    normal_pool = combined[combined["label"] == 0]
    normal_events = normal_pool.sample(n=min(5000, len(normal_pool)), random_state=42)
    processed_df = pd.concat([threat_events, normal_events], ignore_index=True)
    processed_df = processed_df.sort_values(by="date").reset_index(drop=True)
    processed_df = processed_df[["date", "user", "pc", "activity", "label"]]
    processed_df.to_csv(os.path.join(DATASET_DIR, "processed_cert.csv"), index=False)
    print(f"Saved {len(processed_df)} processed CERT rows")

    return scaler, user_le, pc_le


def train_anomaly_detectors():
    print("\n" + "=" * 60)
    print("Training Isolation Forest Anomaly Detectors")
    print("=" * 60)

    if os.path.exists(TON_IOT_PATH):
        print("\n[ANOMALY] Training TON_IoT Isolation Forest...")
        cols = [
            "src_port", "dst_port", "proto", "duration",
            "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "type",
        ]
        ton_df = pd.read_csv(TON_IOT_PATH, usecols=cols)
        ton_normal = ton_df[
            ton_df["type"].astype(str).str.strip().str.lower() == "normal"
        ].copy()

        if len(ton_normal) >= 50:
            for col in ["duration", "src_bytes", "dst_bytes"]:
                ton_normal[col] = pd.to_numeric(
                    ton_normal[col].astype(str).str.replace("-", "0"),
                    errors="coerce",
                ).fillna(0)
            for col in ["src_port", "dst_port", "src_pkts", "dst_pkts"]:
                ton_normal[col] = pd.to_numeric(ton_normal[col], errors="coerce").fillna(0)

            proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
            ton_normal["proto_num"] = (
                ton_normal["proto"].str.lower().map(proto_map).fillna(0).astype(int)
            )

            ton_features = [
                "src_port", "dst_port", "proto_num",
                "duration", "src_bytes", "dst_bytes",
                "src_pkts", "dst_pkts",
            ]
            X_ton = ton_normal[ton_features].head(5000).values.astype(np.float64)

            ton_if_scaler = StandardScaler()
            X_ton_scaled = ton_if_scaler.fit_transform(X_ton)

            ton_if_model = IsolationForest(
                n_estimators=100, contamination=0.05,
                max_samples="auto", random_state=42, n_jobs=-1,
            )
            ton_if_model.fit(X_ton_scaled)

            joblib.dump(ton_if_model, os.path.join(CML_DIR, "if_ton_model.pkl"))
            joblib.dump(ton_if_scaler, os.path.join(CML_DIR, "if_ton_scaler.pkl"))
            joblib.dump(ton_features, os.path.join(CML_DIR, "if_ton_features.pkl"))
            print(f"[ANOMALY] TON_IoT IF trained on {len(X_ton)} normal samples")

    if os.path.exists(PHISHING_PATH):
        print("\n[ANOMALY] Training PhiUSIIL Isolation Forest...")
        phi_df = pd.read_csv(PHISHING_PATH, nrows=50000)
        phi_normal = phi_df[phi_df["label"] == 0].copy()

        phi_features = PHI_FEATURE_COLS
        available_phi = [f for f in phi_features if f in phi_normal.columns]

        if len(phi_normal) >= 50 and len(available_phi) >= 2:
            X_phi = phi_normal[available_phi].head(5000).values.astype(np.float64)

            phi_if_scaler = StandardScaler()
            X_phi_scaled = phi_if_scaler.fit_transform(X_phi)

            phi_if_model = IsolationForest(
                n_estimators=100, contamination=0.05,
                max_samples="auto", random_state=42, n_jobs=-1,
            )
            phi_if_model.fit(X_phi_scaled)

            joblib.dump(phi_if_model, os.path.join(CML_DIR, "if_phi_model.pkl"))
            joblib.dump(phi_if_scaler, os.path.join(CML_DIR, "if_phi_scaler.pkl"))
            joblib.dump(available_phi, os.path.join(CML_DIR, "if_phi_features.pkl"))
            print(f"[ANOMALY] PhiUSIIL IF trained on {len(X_phi)} normal samples")

    cert_processed = os.path.join(DATASET_DIR, "processed_cert.csv")
    if os.path.exists(cert_processed):
        print("\n[ANOMALY] Training CERT Isolation Forest...")
        cert_df = pd.read_csv(cert_processed, nrows=10000)
        cert_normal = cert_df[cert_df["label"] == 0].copy()

        if len(cert_normal) >= 50:
            cert_normal["date"] = pd.to_datetime(cert_normal["date"], errors="coerce")
            cert_normal["hour"] = cert_normal["date"].dt.hour.fillna(0).astype(int)
            cert_normal["dayofweek"] = cert_normal["date"].dt.dayofweek.fillna(0).astype(int)
            cert_normal["is_after_hours"] = (
                (cert_normal["hour"] < 6) | (cert_normal["hour"] > 19)
            ).astype(int)
            cert_normal["is_weekend"] = (cert_normal["dayofweek"] >= 5).astype(int)

            activity_map = {"Logon": 0, "Logoff": 1, "Connect": 2, "Disconnect": 3}
            cert_normal["activity_type"] = (
                cert_normal["activity"].map(activity_map).fillna(0).astype(int)
            )

            cert_if_features = [
                "hour", "dayofweek", "is_after_hours",
                "is_weekend", "activity_type",
            ]
            available_cert = [f for f in cert_if_features if f in cert_normal.columns]

            if len(available_cert) >= 2:
                X_cert = cert_normal[available_cert].head(5000).values.astype(np.float64)

                cert_if_scaler = StandardScaler()
                X_cert_scaled = cert_if_scaler.fit_transform(X_cert)

                cert_if_model = IsolationForest(
                    n_estimators=100, contamination=0.05,
                    max_samples="auto", random_state=42, n_jobs=-1,
                )
                cert_if_model.fit(X_cert_scaled)

                joblib.dump(cert_if_model, os.path.join(CML_DIR, "if_cert_model.pkl"))
                joblib.dump(cert_if_scaler, os.path.join(CML_DIR, "if_cert_scaler.pkl"))
                joblib.dump(available_cert, os.path.join(CML_DIR, "if_cert_features.pkl"))
                print(f"[ANOMALY] CERT IF trained on {len(X_cert)} normal samples")

    print("\n[ANOMALY] All anomaly detectors trained and saved.")


if __name__ == "__main__":
    train_ton_iot()
    train_phishing()
    train_cert()
    train_anomaly_detectors()
    print("\n" + "=" * 60)
    print("All models trained and preprocessors saved successfully!")
    print("=" * 60)