import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_val_predict
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE
import joblib
import os

# Define selected features EnGuardia uses
SELECTED_FEATURES = [
    'dur', 'state', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'dinpkt', 'smean', 'dmean', 'ct_state_ttl', 'ct_srv_dst',
    'ct_flw_http_mthd'
]

SAVE_DIR = 'saved_models'

def main():
    os.makedirs(SAVE_DIR, exist_ok=True)
    df = pd.read_csv('data/UNSW_NB15.csv')
    # Drop irrelevant columns
    df.drop(columns=[col for col in df.columns if 'id' in col.lower() or 'time' in col.lower()], 
            inplace=True, errors='ignore')

    df['service'] = df['service'].replace('-', np.nan)
    df['attack_cat'] = df['attack_cat'].replace('-', np.nan)
    df.dropna(subset=['service', 'attack_cat'], inplace=True)

    y_labels = df['attack_cat'].astype(str)

    # Encode input features
    label_encoders = {}
    for col in SELECTED_FEATURES:
        if df[col].dtype == 'object':
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            label_encoders[col] = le

    label_encoder_y = LabelEncoder()
    y_encoded = label_encoder_y.fit_transform(y_labels)

    X = df[SELECTED_FEATURES].copy()
    y = y_encoded

    X_resampled, y_resampled = SMOTE(random_state=42).fit_resample(X, y)
    print("\nResampled class distribution:", dict(pd.Series(y_resampled).value_counts()))

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_resampled)

    joblib.dump(scaler, f'{SAVE_DIR}/nids_scaler.joblib')

    model = XGBClassifier(
        n_estimators=300,
        learning_rate=0.1,
        max_depth=8,
        subsample=0.8,
        colsample_bytree=0.8,
        objective='multi:softprob',
        num_class=len(label_encoder_y.classes_),
        eval_metric='mlogloss',
        random_state=42
    )

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y_pred_cv = cross_val_predict(model, X_scaled, y_resampled, cv=skf, method='predict')
    print("\nCross-Validation Classification Report:")
    print(classification_report(y_resampled, y_pred_cv, target_names=label_encoder_y.classes_))

    scores = cross_val_score(model, X_scaled, y_resampled, cv=skf, scoring='f1_weighted')
    print(f"\nCross-validated weighted F1 scores: {scores}")
    print(f"Mean F1-score: {scores.mean():.4f}")

    model.fit(X_scaled, y_resampled)

    joblib.dump(model, f'{SAVE_DIR}/nids_xgb_model.joblib')
    joblib.dump(label_encoder_y, f'{SAVE_DIR}/nids_label_encoder.joblib')
    joblib.dump(label_encoders, f'{SAVE_DIR}/nids_input_encoders.joblib')
    joblib.dump(SELECTED_FEATURES, f'{SAVE_DIR}/nids_selected_features.joblib')

    print("\nLabel encoding mapping:")
    for i, label in enumerate(label_encoder_y.classes_):
        print(f"{i}: {label}")

    if 'state' in label_encoders:
        print("\nState encoding mapping:")
        le_state = label_encoders['state']
        for i, class_ in enumerate(le_state.classes_):
            print(f"{i}: {class_}")

    print_sample_predictions()

def print_sample_predictions():
    try:
        df = pd.read_csv('/content/UNSW_NB15.csv')
        df = df.replace('-', np.nan).dropna(subset=['service', 'attack_cat'])

        selected_features = joblib.load(f'{SAVE_DIR}/nids_selected_features.joblib')
        encoders = joblib.load(f'{SAVE_DIR}/nids_input_encoders.joblib')
        label_encoder = joblib.load(f'{SAVE_DIR}/nids_label_encoder.joblib')
        scaler = joblib.load(f'{SAVE_DIR}/nids_scaler.joblib')
        model = joblib.load(f'{SAVE_DIR}/nids_xgb_model.joblib')

        samples = {}
        for label in df['attack_cat'].unique():
            row = df[df['attack_cat'] == label].iloc[0]
            features = {}
            for f in selected_features:
                val = row[f]
                if f in encoders:
                    val = encoders[f].transform([str(val)])[0]
                features[f] = val
            samples[label] = features

        print("\nSample Predictions:")
        for actual, feat_dict in samples.items():
            X_sample = pd.DataFrame([feat_dict])[selected_features]
            X_scaled = scaler.transform(X_sample)
            proba = model.predict_proba(X_scaled)[0]
            pred_idx = np.argmax(proba)
            predicted = label_encoder.inverse_transform([pred_idx])[0]
            confidence = proba[pred_idx]
            print(f"Actual: {actual:15s} → Predicted: {predicted:15s} | Confidence: {confidence:.4f}")

    except Exception as e:
        print(f"Sample prediction failed: {e}")

if __name__ == "__main__":
    main()
