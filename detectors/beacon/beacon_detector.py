"""
PassiveSentinel - Layer L5b: Botnet C2 Beaconing Detector
Analyzes repeated start times per (src, dst, port) using:
1. Discrete Fourier Transform (FFT) for dominant frequency and spectral power share
2. Autocorrelation peak at dominant lag
3. Coefficient of variation CV(IAT) and MAD(IAT)/median
4. Histogram Gradient Boosted Decision Trees (GBM) with timing-jitter data augmentation (up to 20%)
"""

import os
import pickle
import numpy as np
from scipy import fft, signal
from sklearn.ensemble import HistGradientBoostingClassifier
from typing import Dict, Any, Tuple, List, Optional

class BeaconingDetectorL5b:
    def __init__(self, n_estimators: int = 150, learning_rate: float = 0.05):
        self.model = HistGradientBoostingClassifier(
            max_iter=n_estimators,
            max_depth=5,
            learning_rate=learning_rate,
            random_state=42
        )
        self.fitted = False

    @staticmethod
    def extract_beacon_features(timestamps_s: List[float], jitter_augment: bool = False) -> np.ndarray:
        """
        Extracts spectral and autocorrelation regularity features from event start times.
        Returns: [event_count, median_iat, cv_iat, mad_iat_ratio, dominant_freq, power_share, autocorr_peak]
        """
        if len(timestamps_s) < 4:
            return np.zeros(7, dtype=np.float32)

        ts = np.array(sorted(timestamps_s), dtype=float)
        iats = np.diff(ts)

        if jitter_augment:
            jitter = np.random.uniform(-0.20, 0.20, size=len(iats))
            iats = np.maximum(0.01, iats * (1.0 + jitter))

        med_iat = float(np.median(iats))
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
        cv_iat = float(std_iat / (mean_iat + 1e-6))
        
        mad = float(np.median(np.abs(iats - med_iat)))
        mad_ratio = float(mad / (med_iat + 1e-6))

        bin_size = max(1.0, med_iat / 4.0)
        n_bins = min(256, max(16, int((ts[-1] - ts[0]) / bin_size) + 1))
        hist, _ = np.histogram(ts, bins=n_bins)

        fft_vals = np.abs(fft.rfft(hist - np.mean(hist)))
        freqs = fft.rfftfreq(n_bins, d=bin_size)

        if len(fft_vals) > 1:
            dom_idx = int(np.argmax(fft_vals[1:])) + 1
            dom_freq = float(freqs[dom_idx])
            total_power = float(np.sum(fft_vals ** 2))
            power_share = float((fft_vals[dom_idx] ** 2) / (total_power + 1e-6))
        else:
            dom_freq = 0.0
            power_share = 0.0

        autocorr = signal.correlate(hist - np.mean(hist), hist - np.mean(hist), mode="full")
        mid = len(autocorr) // 2
        pos_ac = autocorr[mid + 1:]
        if len(pos_ac) > 0 and pos_ac[0] != 0:
            norm_ac = pos_ac / (autocorr[mid] + 1e-6)
            peaks, _ = signal.find_peaks(norm_ac)
            ac_peak = float(np.max(norm_ac[peaks])) if len(peaks) > 0 else 0.0
        else:
            ac_peak = 0.0

        return np.array([
            float(len(timestamps_s)),
            med_iat,
            cv_iat,
            mad_ratio,
            dom_freq,
            power_share,
            ac_peak
        ], dtype=np.float32)

    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: Optional[np.ndarray] = None, y_val: Optional[np.ndarray] = None):
        print("Training L5b Beaconing GBM Detector...")
        self.model.fit(X_train, y_train)
        self.fitted = True

    def predict_beacon_probability(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns: (beacon_probabilities in [0, 1], binary_decision)
        """
        if not self.fitted:
            raise ValueError("L5b detector must be trained before inference.")
        probs = self.model.predict_proba(features)[:, 1]
        preds = (probs >= 0.5).astype(int)
        return probs, preds

    def save(self, filepath: str):
        with open(filepath, "wb") as f:
            pickle.dump(self.model, f)

    def load(self, filepath: str):
        with open(filepath, "rb") as f:
            self.model = pickle.load(f)
        self.fitted = True
