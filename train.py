# Final version of train.py, focused only on the URL Random Forest model.

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from url_analyzer import extract_lexical_features # Use the updated extractor

def train_url_model():
    """Trains a Random Forest model on the URL dataset using lexical features."""
    print("--- Training URL Lexical Model (Random Forest) ---")
    try:
        data = pd.read_csv("data/url_data_full.csv")
        print("1. Extracting lexical features from URLs...")
        features_df = pd.DataFrame(list(data['url'].apply(extract_lexical_features)))
        y = data['result']
        X = features_df
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        print(f"2. Training Random Forest model...")
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
        model.fit(X_train, y_train)
        print(f"   Model Accuracy: {model.score(X_test, y_test):.2%}")
        model_payload = {'model': model, 'features': list(X.columns)}
        joblib.dump(model_payload, "url_rf_model.pkl")
        print("✅ URL Random Forest model trained successfully.")
    except FileNotFoundError:
        print("❌ Error: 'data/url_data_full.csv' not found.")
    except Exception as e:
        print(f"❌ URL model training failed: {e}")

if __name__ == "__main__":
    train_url_model()