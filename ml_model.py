# model/ml_model.py
# Machine Learning model access layer for predicting intrusions using CICIDS2017 RandomForest

import os
import time
import numpy as np
import pandas as pd
import joblib
from typing import List, Dict, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "ids_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "features.pkl")

# Global variables for model assets
model = None
encoder = None
features_list = None

def load_assets():
    """Loads model, label encoder, and feature list from disk if not already loaded."""
    global model, encoder, features_list
    if model is not None and encoder is not None and features_list is not None:
        return
        
    if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH) or not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(
            f"Required model asset files are missing at project root. "
            f"Expected {MODEL_PATH}, {ENCODER_PATH}, and {FEATURES_PATH}."
        )
        
    model = joblib.load(MODEL_PATH)
    # Set n_jobs to 1 to prevent thread thrashing in web server workers
    model.n_jobs = 1
    encoder = joblib.load(ENCODER_PATH)
    features_list = joblib.load(FEATURES_PATH)

def get_classes() -> List[str]:
    """Returns the list of target classes predicted by the model."""
    load_assets()
    return list(encoder.classes_)

def get_expected_features_count() -> int:
    """Returns the number of expected numerical features."""
    load_assets()
    return len(features_list)

def validate_and_impute(features: List[Optional[float]]) -> Tuple[List[float], int, List[int]]:
    """Validates features length, type, and imputes missing/inf/nan values."""
    load_assets()
    expected_len = len(features_list)
    if len(features) != expected_len:
        raise ValueError(f"Invalid feature vector length: Expected {expected_len}, got {len(features)}")
    
    sanitized = []
    imputed_indices = []
    
    for idx, val in enumerate(features):
        if val is None:
            sanitized.append(0.0)
            imputed_indices.append(idx)
        else:
            try:
                fval = float(val)
                if np.isnan(fval) or np.isinf(fval):
                    sanitized.append(0.0)
                    imputed_indices.append(idx)
                else:
                    sanitized.append(fval)
            except (ValueError, TypeError):
                feat_name = features_list[idx] if idx < len(features_list) else f"Feature {idx}"
                raise ValueError(f"Invalid numerical value at index {idx} ('{feat_name}'): {val}")
                
    return sanitized, len(imputed_indices), imputed_indices

def predict_single(features: List[Optional[float]]) -> Dict[str, Any]:
    """
    Predicts intrusion class for a single feature vector.
    Returns details: prediction label, class probabilities, imputed count, imputed indices, latency.
    """
    load_assets()
    start_time = time.time()
    
    sanitized_features, imputed_count, imputed_indices = validate_and_impute(features)
    
    # Convert to DataFrame with feature names to match training header ordering
    feat_df = pd.DataFrame([sanitized_features], columns=features_list)
    
    # Predict
    pred_idx = model.predict(feat_df)[0]
    pred_label = encoder.inverse_transform([pred_idx])[0]
    
    # Class probabilities
    prob_array = model.predict_proba(feat_df)[0]
    class_probs = {
        class_name: float(prob)
        for class_name, prob in zip(encoder.classes_, prob_array)
    }
    
    latency = (time.time() - start_time) * 1000.0
    
    return {
        "prediction": pred_label,
        "class_probabilities": class_probs,
        "imputed_count": imputed_count,
        "imputed_indices": imputed_indices,
        "latency_ms": latency
    }

def predict_batch(inputs: List[List[Optional[float]]]) -> Dict[str, Any]:
    """
    Predicts intrusion classes for a list of feature vectors.
    Returns a dictionary with list of prediction results and total batch latency.
    """
    load_assets()
    start_time = time.time()
    
    if not inputs:
        raise ValueError("Input batch cannot be empty.")
        
    sanitized_batch = []
    imputed_counts = []
    imputed_indices_list = []
    
    for idx, item in enumerate(inputs):
        try:
            sanitized, imp_cnt, imp_idx = validate_and_impute(item)
            sanitized_batch.append(sanitized)
            imputed_counts.append(imp_cnt)
            imputed_indices_list.append(imp_idx)
        except Exception as e:
            raise ValueError(f"Validation error at batch index {idx}: {str(e)}")
            
    feat_df = pd.DataFrame(sanitized_batch, columns=features_list)
    pred_indices = model.predict(feat_df)
    pred_labels = encoder.inverse_transform(pred_indices)
    prob_arrays = model.predict_proba(feat_df)
    
    predictions = []
    for i in range(len(inputs)):
        class_probs = {
            class_name: float(prob)
            for class_name, prob in zip(encoder.classes_, prob_arrays[i])
        }
        predictions.append({
            "prediction": pred_labels[i],
            "class_probabilities": class_probs,
            "imputed_count": imputed_counts[i],
            "imputed_indices": imputed_indices_list[i]
        })
        
    latency = (time.time() - start_time) * 1000.0
    
    return {
        "predictions": predictions,
        "total_records": len(inputs),
        "latency_ms": latency
    }
