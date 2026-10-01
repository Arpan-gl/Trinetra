"""
PassiveSentinel - Layer L5e: Autoencoder Anomaly Gate (Unknown Threats)
Dense Autoencoder: input (~16..40) -> 32 -> 16 -> 8 -> 16 -> 32 -> output (~16..40)
Trained strictly on BENIGN training flows with MSE loss.
Threshold is set at the 99.5th percentile of benign validation reconstruction error.
"""

import os
import torch
import torch.nn as nn
import numpy as np
from typing import Tuple, Dict, Any

class DenseAutoencoder(nn.Module):
    def __init__(self, input_dim: int = 16):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction

class AutoencoderGateL5e:
    def __init__(self, input_dim: int = 16, lr: float = 1e-3, weight_decay: float = 1e-4):
        self.input_dim = input_dim
        self.model = DenseAutoencoder(input_dim)
        self.criterion = nn.MSELoss(reduction="none")
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=weight_decay)
        self.threshold = 1.0
        self.fitted = False

    def train_on_benign(self, train_benign_x: np.ndarray, val_benign_x: np.ndarray, 
                        epochs: int = 15, batch_size: int = 256) -> Dict[str, Any]:
        """
        Trains autoencoder strictly on benign flows; computes 99.5th percentile threshold on val benign.
        """
        self.model.train()
        tensor_x = torch.tensor(train_benign_x, dtype=torch.float32)
        dataset = torch.utils.data.TensorDataset(tensor_x)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        for epoch in range(epochs):
            total_loss = 0.0
            for (batch_x,) in loader:
                self.optimizer.zero_grad()
                recon = self.model(batch_x)
                loss = torch.mean(torch.sum((batch_x - recon) ** 2, dim=-1))
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()

        # Compute threshold on benign validation set (99.5th percentile)
        self.model.eval()
        with torch.no_grad():
            v_x = torch.tensor(val_benign_x, dtype=torch.float32)
            v_recon = self.model(v_x)
            val_errors = torch.mean((v_x - v_recon) ** 2, dim=-1).cpu().numpy()
            self.threshold = float(np.percentile(val_errors, 99.5))

        self.fitted = True
        return {
            "threshold_p99_5": self.threshold,
            "val_mean_error": float(np.mean(val_errors)),
            "val_max_error": float(np.max(val_errors))
        }

    def score(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Scores input flows.
        Returns: (normalized_anomaly_scores [0, 1], binary_flags)
        """
        self.model.eval()
        with torch.no_grad():
            tx = torch.tensor(x, dtype=torch.float32)
            recon = self.model(tx)
            errors = torch.mean((tx - recon) ** 2, dim=-1).cpu().numpy()
            
            # Normalize score relative to threshold so 1.0 represents threshold
            scores = np.clip(errors / (self.threshold + 1e-6), 0.0, 10.0) / 10.0
            flags = (errors >= self.threshold).astype(int)
            return scores, flags

    def save(self, filepath: str):
        torch.save({
            "model_state": self.model.state_dict(),
            "input_dim": self.input_dim,
            "threshold": self.threshold
        }, filepath)

    def load(self, filepath: str):
        data = torch.load(filepath, map_location="cpu", weights_only=True)
        self.input_dim = data["input_dim"]
        self.model = DenseAutoencoder(self.input_dim)
        self.model.load_state_dict(data["model_state"])
        self.threshold = data["threshold"]
        self.fitted = True
