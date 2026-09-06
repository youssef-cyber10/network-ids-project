"""
Train a RandomForest model for network intrusion detection.
Report Precision/Recall/F1 (preferred over Accuracy for security use-cases
because false negatives are more severe than false positives).
"""
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from preprocess import load_raw, add_binary_and_category_labels, encode_categorical, get_features_and_target

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


def train_and_evaluate():
    print("[1/5] Loading data...")
    train_df = add_binary_and_category_labels(load_raw("train"))
    test_df = add_binary_and_category_labels(load_raw("test"))

    print("[2/5] Encoding categorical columns...")
    train_df, test_df, encoders = encode_categorical(train_df, test_df)

    print("[3/5] Preparing X and y...")
    X_train, y_train = get_features_and_target(train_df, target_col="is_attack")
    X_test, y_test = get_features_and_target(test_df, target_col="is_attack")

    print("[4/5] Training RandomForest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",  # مهم: البيانات غير متوازنة (U2R نادر جدًا)
    )
    model.fit(X_train, y_train)

    print("[5/5] Evaluating on test set (unseen during training)...")
    y_pred = model.predict(X_test)

    print("\n" + "=" * 50)
    print("Performance report (Normal=0 / Attack=1):")
    print("=" * 50)
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Most important features contributing to decisions - useful for analysis
    importances = pd.Series(model.feature_importances_, index=X_train.columns)
    print("\nTop 10 important features:")
    print(importances.sort_values(ascending=False).head(10))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, "rf_model.joblib"))
    joblib.dump(encoders, os.path.join(MODEL_DIR, "encoders.joblib"))
    print(f"\n[saved] model and encoders saved to {MODEL_DIR}")

    return model, encoders


if __name__ == "__main__":
    train_and_evaluate()
