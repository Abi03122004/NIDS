# core/alert_engine.py
# Processes network flow predictions and handles colorized logging and critical alert escalation

import time
from collections import deque
import colorama
from colorama import Fore, Back, Style

# Initialize Colorama to ensure colors work on Windows terminal
colorama.init(autoreset=True)

class AlertEngine:
    """Processes network flow predictions and handles colorized logging and critical alert escalation."""
    def __init__(self, window_size_seconds: float = 5.0, count_threshold: int = 5):
        self.window_size = window_size_seconds
        self.threshold = count_threshold
        
        # Track history of timestamps for each attack category to calculate thresholds
        self.attack_history = {
            "Bot": deque(),
            "Brute Force": deque(),
            "DDoS": deque(),
            "DoS": deque(),
            "PortScan": deque(),
            "Web Attack": deque(),
        }

    def process_prediction(self, prediction: str, probabilities: dict):
        """Processes a single prediction, prints colored output, and checks escalation thresholds."""
        current_time = time.time()
        
        # Prune old timestamps outside the sliding window
        for attack_type in self.attack_history:
            history = self.attack_history[attack_type]
            while history and (current_time - history[0] > self.window_size):
                history.popleft()

        # Handle Benign flow
        if prediction == "BENIGN":
            confidence = probabilities.get("BENIGN", 1.0)
            print(f"{Fore.GREEN}[INFO] BENIGN (Confidence: {confidence:.2%})")
            return

        # Handle Attack detection
        confidence = probabilities.get(prediction, 0.0)
        
        # Select color based on severity
        if prediction in ["DDoS", "DoS", "PortScan"]:
            color = Fore.RED + Style.BRIGHT
        else:
            color = Fore.YELLOW + Style.BRIGHT
            
        print(f"{color}[ALERT] {prediction} Detected! (Confidence: {confidence:.2%})")

        # Track event in history and check if we hit threshold for escalation
        if prediction in self.attack_history:
            self.attack_history[prediction].append(current_time)
            recent_count = len(self.attack_history[prediction])
            
            if recent_count >= self.threshold:
                print(
                    f"{Back.RED}{Fore.WHITE}{Style.BRIGHT}"
                    f"[CRITICAL ALERT] Potential {prediction.upper()} FLOOD/SCAN activity detected! "
                    f"({recent_count} events in last {self.window_size} seconds)"
                )
