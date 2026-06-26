# core/logger.py
# Logger initialization with structured JSON log files and colored console logs

import os
import json
import logging
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "predictions.log")

class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects for file storage."""
    def format(self, record):
        if isinstance(record.msg, dict):
            obj = record.msg
        else:
            obj = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "message": record.getMessage()
            }
        return json.dumps(obj)

class ConsoleFormatter(logging.Formatter):
    """Formats log records as readable string summaries for console output."""
    def format(self, record):
        if isinstance(record.msg, dict):
            msg_dict = record.msg
            endpoint = msg_dict.get("endpoint", "N/A")
            status = msg_dict.get("status", "N/A")
            latency = msg_dict.get("latency_ms", 0.0)
            pred = msg_dict.get("prediction", None)
            imp_cnt = msg_dict.get("imputed_count", msg_dict.get("total_imputed", 0))
            
            if pred:
                return f"[{record.levelname}] {endpoint} - Status: {status} | Prediction: {pred} | Imputed: {imp_cnt} | Latency: {latency:.2f}ms"
            else:
                total_rec = msg_dict.get("total_records", 0)
                return f"[{record.levelname}] {endpoint} - Status: {status} | Records: {total_rec} | Total Imputed: {imp_cnt} | Latency: {latency:.2f}ms"
        
        return f"[{record.levelname}] {record.getMessage()}"

# Setup Logger
logger = logging.getLogger("ids_api")
logger.setLevel(logging.INFO)
logger.propagate = False  # Prevent double logging in standard output

if not logger.handlers:
    # File Handler for structured JSON
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(JSONFormatter())

    # Console Handler for clean console output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(ConsoleFormatter())

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
