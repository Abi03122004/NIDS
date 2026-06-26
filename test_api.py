import os
import json
import unittest
import numpy as np
import joblib
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

BASE_URL = "http://127.0.0.1:8000"

class TestIDSAssetsAndAPI(unittest.TestCase):
    
    # ==========================================
    # Phase 1: Local ML Asset Validation Checks
    # ==========================================
    
    def test_01_model_loading(self):
        """Verify that the random forest model loads successfully and matches specs."""
        self.assertTrue(os.path.exists("ids_model.pkl"), "ids_model.pkl is missing!")
        model = joblib.load("ids_model.pkl")
        model.n_jobs = 1
        self.assertIsInstance(model, RandomForestClassifier, "Model is not a RandomForestClassifier!")
        self.assertEqual(model.n_features_in_, 78, f"Model expects {model.n_features_in_} features instead of 78!")
        self.assertTrue(hasattr(model, "predict_proba"), "Model does not support predict_proba!")

    def test_02_encoder_loading(self):
        """Verify that the label encoder loads successfully and has expected classes."""
        self.assertTrue(os.path.exists("label_encoder.pkl"), "label_encoder.pkl is missing!")
        encoder = joblib.load("label_encoder.pkl")
        self.assertIsInstance(encoder, LabelEncoder, "Encoder is not a LabelEncoder!")
        
        expected_classes = sorted(['BENIGN', 'Bot', 'Brute Force', 'DDoS', 'DoS', 'PortScan', 'Web Attack'])
        actual_classes = sorted(list(encoder.classes_))
        self.assertEqual(actual_classes, expected_classes, "Label encoder classes do not match expected list!")

    def test_03_feature_ordering(self):
        """Verify features.pkl structure and features count match model requirements."""
        self.assertTrue(os.path.exists("features.pkl"), "features.pkl is missing!")
        features = joblib.load("features.pkl")
        self.assertIsInstance(features, list, "Features list is not a Python list!")
        self.assertEqual(len(features), 78, f"Expected 78 features in list, got {len(features)}!")
        
        # Verify first and last feature names as check
        self.assertEqual(features[0], "Destination Port")
        self.assertEqual(features[-1], "Idle Min")

    def test_04_prediction_consistency(self):
        """Verify that model predictions are deterministic and consistent on identical inputs."""
        model = joblib.load("ids_model.pkl")
        model.n_jobs = 1
        
        dummy_input_1 = np.zeros((1, 78))
        dummy_input_2 = np.zeros((1, 78))
        
        # Predict class index
        pred_1 = model.predict(dummy_input_1)[0]
        pred_2 = model.predict(dummy_input_2)[0]
        self.assertEqual(pred_1, pred_2, "Model class predictions are not consistent on identical inputs!")
        
        # Predict probabilities
        prob_1 = model.predict_proba(dummy_input_1)[0]
        prob_2 = model.predict_proba(dummy_input_2)[0]
        np.testing.assert_array_almost_equal(prob_1, prob_2, decimal=6, err_msg="Model prediction probabilities are not consistent!")


    # ==========================================
    # Phase 2: Live API Endpoint Testing
    # ==========================================

    def setUp(self):
        # Load sample requests file
        self.assertTrue(os.path.exists("sample_requests.json"), "sample_requests.json is missing!")
        with open("sample_requests.json", "r") as f:
            self.samples = json.load(f)

    def test_05_api_root(self):
        """Test the GET / endpoint returns metadata."""
        try:
            r = requests.get(f"{BASE_URL}/")
            self.assertEqual(r.status_code, 200, "Root API endpoint returned non-200 status code.")
            data = r.json()
            self.assertIn("documentation", data)
            self.assertIn("endpoints", data)
            self.assertIn("GET /history", data["endpoints"])
            self.assertIn("GET /stats", data["endpoints"])
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running at http://127.0.0.1:8000. Skipping live API test.")

    def test_06_api_health(self):
        """Test the GET /health endpoint check."""
        try:
            r = requests.get(f"{BASE_URL}/health")
            self.assertEqual(r.status_code, 200, "Health check returned non-200 status code.")
            data = r.json()
            self.assertEqual(data["status"], "healthy")
            self.assertTrue(data["model_loaded"])
            self.assertEqual(data["features_expected"], 78)
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_07_api_predict_valid(self):
        """Test single flow prediction on valid benign input."""
        try:
            payload = self.samples["valid_benign"]
            r = requests.post(f"{BASE_URL}/predict", json=payload)
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertIn("prediction", data)
            self.assertIn("class_probabilities", data)
            self.assertEqual(data["imputed_count"], 0)
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_08_api_predict_imputed(self):
        """Test single flow prediction with missing/invalid features (None, NaN, Inf) to test imputation."""
        try:
            payload = self.samples["imputed_request"]
            r = requests.post(f"{BASE_URL}/predict", json=payload)
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["imputed_count"], 3)
            self.assertEqual(data["imputed_indices"], [5, 12, 20])
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_09_api_predict_wrong_length(self):
        """Test that single prediction fails when feature count is wrong (e.g., 77 features)."""
        try:
            payload = self.samples["wrong_feature_count"]
            r = requests.post(f"{BASE_URL}/predict", json=payload)
            self.assertEqual(r.status_code, 400)
            data = r.json()
            self.assertIn("Invalid feature vector length", data["detail"])
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_10_api_predict_invalid_type(self):
        """Test that single prediction fails with 422 error when a feature is of invalid type (string)."""
        try:
            payload = self.samples["invalid_input_type"]
            r = requests.post(f"{BASE_URL}/predict", json=payload)
            self.assertEqual(r.status_code, 422)
            data = r.json()
            self.assertIn("unable to parse string as a number", data["detail"][0]["msg"])
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_11_api_predict_empty(self):
        """Test that single prediction fails when features list is empty."""
        try:
            payload = self.samples["empty_request"]
            r = requests.post(f"{BASE_URL}/predict", json=payload)
            self.assertEqual(r.status_code, 400)
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_12_api_batch_predict(self):
        """Test batch prediction with multiple valid records."""
        try:
            payload = {
                "inputs": [
                    self.samples["valid_benign"]["features"],
                    self.samples["imputed_request"]["features"]
                ]
            }
            r = requests.post(f"{BASE_URL}/batch_predict", json=payload)
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["total_records"], 2)
            self.assertEqual(len(data["predictions"]), 2)
            self.assertEqual(data["predictions"][0]["imputed_count"], 0)
            self.assertEqual(data["predictions"][1]["imputed_count"], 3)
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_13_api_history(self):
        """Test GET /history endpoint returns list of records and supports filtering/pagination."""
        try:
            # 1. Fetch history with default limit
            r = requests.get(f"{BASE_URL}/history")
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertTrue(data["success"])
            self.assertIn("records", data)
            self.assertIn("count", data)
            
            # 2. Test pagination limits
            r_limit = requests.get(f"{BASE_URL}/history?limit=1")
            self.assertEqual(r_limit.status_code, 200)
            data_limit = r_limit.json()
            self.assertLessEqual(len(data_limit["records"]), 1)
            
            # 3. Test filtering by invalid severity returns 400
            r_invalid = requests.get(f"{BASE_URL}/history?severity=INVALID")
            self.assertEqual(r_invalid.status_code, 400)
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_14_api_stats(self):
        """Test GET /stats endpoint returns valid aggregates."""
        try:
            r = requests.get(f"{BASE_URL}/stats")
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertTrue(data["success"])
            self.assertIn("statistics", data)
            
            stats = data["statistics"]
            self.assertIn("total_records", stats)
            self.assertIn("class_distribution", stats)
            self.assertIn("severity_distribution", stats)
            self.assertIn("average_latency_ms", stats)
            self.assertIn("total_imputed_features", stats)
            self.assertIn("attacks_last_hour", stats)
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

    def test_15_database_persistence(self):
        """Test that predictions are successfully persisted to SQLite database via API."""
        try:
            # Get initial count
            r_init = requests.get(f"{BASE_URL}/stats")
            self.assertEqual(r_init.status_code, 200)
            init_count = r_init.json()["statistics"]["total_records"]
            
            # Send a new prediction payload
            payload = self.samples["valid_benign"]
            r_pred = requests.post(f"{BASE_URL}/predict", json=payload)
            self.assertEqual(r_pred.status_code, 200)
            
            # Verify total records count is incremented by 1
            r_final = requests.get(f"{BASE_URL}/stats")
            self.assertEqual(r_final.status_code, 200)
            final_count = r_final.json()["statistics"]["total_records"]
            self.assertEqual(final_count, init_count + 1, "Prediction record count did not increment in database!")
            
            # Verify the last record matches our prediction
            r_hist = requests.get(f"{BASE_URL}/history?limit=1")
            self.assertEqual(r_hist.status_code, 200)
            records = r_hist.json()["records"]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["prediction"], r_pred.json()["prediction"])
        except requests.exceptions.ConnectionError:
            self.skipTest("API Server is not running. Skipping live API test.")

if __name__ == "__main__":
    unittest.main()
