"""
NSL-KDD data preprocessing: loading, encoding categorical columns, and
preparing X, y for training.
"""
import os
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from columns import COLUMN_NAMES, ATTACK_CATEGORY

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_raw(split="train"):
    filename = "KDDTrain+.txt" if split == "train" else "KDDTest+.txt"
    path = os.path.join(DATA_DIR, filename)
    df = pd.read_csv(path, names=COLUMN_NAMES)
    df = df.drop(columns=["difficulty"])  # عمود غير مفيد للتصنيف
    return df


def add_binary_and_category_labels(df):
    """Add two columns: `is_attack` (0/1) and `attack_category`
    (DoS/Probe/R2L/U2R/normal).
    """
    df = df.copy()
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY).fillna("Unknown")
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


def encode_categorical(df_train, df_test, categorical_cols=("protocol_type", "service", "flag")):
    """
    Encode categorical columns using the same LabelEncoder for train and test
    (important: this handles categories present in test but not in train).
    """
    encoders = {}
    df_train = df_train.copy()
    df_test = df_test.copy()

    for col in categorical_cols:
        le = LabelEncoder()
        combined = pd.concat([df_train[col], df_test[col]], axis=0)
        le.fit(combined)
        df_train[col] = le.transform(df_train[col])
        df_test[col] = le.transform(df_test[col])
        encoders[col] = le

    return df_train, df_test, encoders


def get_features_and_target(df, target_col="is_attack"):
    drop_cols = ["label", "attack_category", "is_attack"]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y = df[target_col]
    return X, y


if __name__ == "__main__":
    train_df = add_binary_and_category_labels(load_raw("train"))
    test_df = add_binary_and_category_labels(load_raw("test"))
    print("Train shape:", train_df.shape)
    print("Test shape:", test_df.shape)
    print("\nCategory distribution in training set:")
    print(train_df["attack_category"].value_counts())
