#!/usr/bin/env python3

import argparse
import warnings
from pathlib import Path

import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold, train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
import joblib

warnings.filterwarnings("ignore", category=UserWarning)

# ========= إعدادات =========
ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "workspace" / "features_dataset.csv"
MODEL_DIR = ROOT / "workspace" / "model"
MODEL_PATH = MODEL_DIR / "trojan_rf.joblib"
FEATURE_LIST_PATH = MODEL_DIR / "feature_list.txt"


def validate_dataset(df: pd.DataFrame) -> bool:
    """التحقق من صحة مجموعة البيانات"""
    if df.empty:
        print("[!] Dataset is empty")
        return False
    
    if "label" not in df.columns:
        print("[!] 'label' column not found")
        return False
    
    # التحقق من القيم الفارغة
    null_ratio = df.isnull().sum().sum() / (df.shape[0] * df.shape[1])
    if null_ratio > 0.5:
        print(f"[!] Too many null values: {null_ratio:.2%}")
        return False
    
    # التحقق من التوزيع
    class_counts = df["label"].value_counts()
    print("\n[*] Class distribution:")
    for cls, count in class_counts.items():
        print(f"  {cls:12s}: {count:4d} ({count/len(df):.1%})")
    
    if class_counts.min() < 2:
        print("[!] Some classes have less than 2 samples")
        return False
    
    return True


def fit_and_report(model, X_train, X_test, y_train, y_test, note=""):
    """تدريب النموذج وطباعة التقرير"""
    print(f"\n[*] Training {note}...")
    model.fit(X_train, y_train)
    
    if len(X_test):
        y_pred = model.predict(X_test)
        print(f"\n[*] {note} Classification Report:")
        print(classification_report(y_test, y_pred, zero_division=0))
        print(f"\n[*] Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        # F1 Score
        f1 = f1_score(y_test, y_pred, average="macro")
        print(f"\n[*] Macro F1 Score: {f1:.4f}")
    
    return model


def analyze_feature_importance(model, feature_names, top_n=20):
    """تحليل أهمية الخصائص"""
    try:
        clf = model.named_steps["clf"]
        importances = clf.feature_importances_
        
        # ترتيب الخصائص حسب الأهمية
        indices = np.argsort(importances)[::-1]
        
        print(f"\n[*] Top {top_n} Most Important Features:")
        print("-" * 60)
        for i, idx in enumerate(indices[:top_n], 1):
            print(f"{i:2d}. {feature_names[idx]:30s}: {importances[idx]:.4f}")
        print("-" * 60)
        
        # حفظ التحليل
        importance_df = pd.DataFrame({
            "feature": feature_names,
            "importance": importances
        }).sort_values("importance", ascending=False)
        
        importance_path = MODEL_DIR / "feature_importance.csv"
        importance_df.to_csv(importance_path, index=False)
        print(f"[*] Feature importance saved to: {importance_path}")
        
    except Exception as e:
        print(f"[!] Could not analyze feature importance: {e}")


def main():
    parser = argparse.ArgumentParser(description="Train Trojan detection model")
    parser.add_argument("--fast", action="store_true", 
                       help="Use RandomizedSearchCV for faster training")
    parser.add_argument("--no_cv", action="store_true", 
                       help="Skip cross-validation, train on full dataset")
    parser.add_argument("--cv_splits", type=int, default=3, 
                       help="Number of CV folds (default: 3)")
    parser.add_argument("--n_iter", type=int, default=16, 
                       help="Number of RandomizedSearch iterations (default: 16)")
    parser.add_argument("--test_size", type=float, default=0.25,
                       help="Test set size (default: 0.25)")
    args = parser.parse_args()
    
    # قراءة البيانات
    if not DATA_PATH.exists():
        raise SystemExit(f"[!] Dataset not found: {DATA_PATH}\nPlease run features_from_zeek.py first")
    
    print(f"[*] Loading dataset from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    print(f"[*] Dataset shape: {df.shape}")
    
    # التحقق من صحة البيانات
    if not validate_dataset(df):
        raise SystemExit("[!] Dataset validation failed")
    
    # فصل الخصائص والتصنيفات
    y = df["label"]
    X = df.drop(columns=["label"])
    
    print(f"\n[*] Features: {X.shape[1]}")
    print(f"[*] Samples: {X.shape[0]}")
    
    # إعداد Preprocessor
    num_cols = X.columns.tolist()
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", Pipeline([
                ("impute", SimpleImputer(strategy="median")),
                ("scale", StandardScaler(with_mean=False))
            ]), num_cols)
        ],
        remainder="drop"
    )
    
    # إعداد النموذج الأساسي
    base_rf = RandomForestClassifier(
        n_estimators=400,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )
    
    # بناء Pipeline
    pipe = Pipeline([
        ("pre", preprocessor),
        ("clf", base_rf)
    ])
    
    # التحقق من حجم العينات
    min_per_class = y.value_counts().min()
    few_samples = (min_per_class < 2) or (y.nunique() < 2) or (len(y) < 8)
    
    # التدريب
    try:
        if few_samples or args.no_cv:
            if few_samples:
                print("\n[!] Few samples detected. Training on full dataset without CV.")
            else:
                print("\n[!] --no_cv enabled. Training on full dataset.")
            
            pipe.fit(X, y)
            
        elif args.fast:
            n_splits = max(2, min(args.cv_splits, min_per_class))
            print(f"\n[*] Using RandomizedSearchCV:")
            print(f"    - Iterations: {args.n_iter}")
            print(f"    - CV Folds: {n_splits}")
            
            param_dist = {
                "clf__n_estimators": [300, 400, 600],
                "clf__max_depth": [None, 8, 16, 24],
                "clf__min_samples_leaf": [1, 2, 4],
                "clf__max_features": ["sqrt", 0.5, None],
                "clf__class_weight": ["balanced", "balanced_subsample"],
                "clf__min_samples_split": [2, 4, 8],
                "clf__bootstrap": [True, False],
            }
            
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            rs = RandomizedSearchCV(
                pipe, param_dist, 
                n_iter=args.n_iter, 
                cv=cv,
                scoring="f1_macro", 
                n_jobs=-1, 
                random_state=42, 
                verbose=1
            )
            
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=args.test_size, random_state=42, stratify=y
            )
            
            rs.fit(X_train, y_train)
            print(f"\n[*] Best parameters: {rs.best_params_}")
            print(f"[*] Best CV score: {rs.best_score_:.4f}")
            
            pipe = rs.best_estimator_
            fit_and_report(pipe, X_train, X_test, y_train, y_test, note="Best Model")
            
        else:
            print(f"\n[*] Simple train/test split ({int((1-args.test_size)*100)}/{int(args.test_size*100)})")
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=args.test_size, random_state=42, stratify=y
            )
            fit_and_report(pipe, X_train, X_test, y_train, y_test, note="Holdout")
    
    except Exception as e:
        print(f"[!] Training failed: {e}")
        raise
    
    finally:
        # حفظ النموذج
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipe, MODEL_PATH)
        print(f"\n[*] Model saved to: {MODEL_PATH}")
        
        # حفظ قائمة الخصائص (بصيغة صحيحة مفصولة بفواصل)
        FEATURE_LIST_PATH.write_text(",".join(X.columns))
        print(f"[*] Feature list saved to: {FEATURE_LIST_PATH}")
        
        # تحليل أهمية الخصائص
        analyze_feature_importance(pipe, X.columns.tolist())
        
        print("\n[✓] Training completed successfully!")


if __name__ == "__main__":
    main()
