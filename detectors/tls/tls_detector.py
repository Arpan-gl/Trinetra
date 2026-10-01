"""
PassiveSentinel - Layer L5d: TLS/QUIC Sequence Model (Metadata Only)
Analyzes cleartext handshake metadata and first 32 packet dynamics without payload decryption:
1. Sequence of first 32 packets: (signed_size / MTU, log1p_iat_ms, direction) -> (32, 3)
2. 1D-CNN with 3 conv blocks (64 channels each) + fingerprint embedding (16-dim)
3. Outputs malicious encrypted session probability in [0, 1]
"""

import os
import torch
import torch.nn as nn
import numpy as np
from typing import Dict, Any, Tuple

class TLSSequenceCNN(nn.Module):
    def __init__(self, in_channels: int = 3, seq_len: int = 32, num_fingerprints: int = 256, embed_dim: int = 16):
        super().__init__()
        self.fp_embed = nn.Embedding(num_fingerprints, embed_dim, padding_idx=0)
        
        self.conv_blocks = nn.Sequential(
            nn.Conv1d(in_channels, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.MaxPool1d(2),
            
            nn.Conv1d(64, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.MaxPool1d(2),

            nn.Conv1d(64, 64, kernel_size=3, padding=1),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1)
        )
        
        self.fc = nn.Sequential(
            nn.Linear(64 + embed_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 2)  # Binary: 0=benign encrypted, 1=malware encrypted
        )

    def forward(self, seq: torch.Tensor, fp_id: torch.Tensor) -> torch.Tensor:
        # seq: (batch, 3, 32)
        conv_out = self.conv_blocks(seq).squeeze(-1)  # (batch, 64)
        fp_emb = self.fp_embed(fp_id)                 # (batch, embed_dim)
        cat = torch.cat([conv_out, fp_emb], dim=-1)
        logits = self.fc(cat)
        return logits

class TLSDetectorL5d:
    def __init__(self):
        self.model = TLSSequenceCNN()
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=1e-3, weight_decay=1e-2)
        self.criterion = nn.CrossEntropyLoss()
        self.fitted = False

    def train(self, seq_train: np.ndarray, fp_train: np.ndarray, labels: np.ndarray, 
              epochs: int = 10, batch_size: int = 128):
        print("Training L5d TLS/QUIC Sequence 1D-CNN Model...")
        t_seq = torch.tensor(seq_train, dtype=torch.float32).transpose(1, 2)  # (batch, 3, 32)
        t_fp = torch.tensor(fp_train, dtype=torch.long)
        t_y = torch.tensor(labels, dtype=torch.long)
        
        dataset = torch.utils.data.TensorDataset(t_seq, t_fp, t_y)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.model.train()
        for epoch in range(epochs):
            for b_seq, b_fp, b_y in loader:
                self.optimizer.zero_grad()
                out = self.model(b_seq, b_fp)
                loss = self.criterion(out, b_y)
                loss.backward()
                self.optimizer.step()
        self.fitted = True

    def predict_proba(self, seq: np.ndarray, fp_id: np.ndarray) -> np.ndarray:
        self.model.eval()
        with torch.no_grad():
            t_seq = torch.tensor(seq, dtype=torch.float32).transpose(1, 2)
            t_fp = torch.tensor(fp_id, dtype=torch.long)
            logits = self.model(t_seq, t_fp)
            probs = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
            return probs

    def save(self, filepath: str):
        torch.save(self.model.state_dict(), filepath)

    def load(self, filepath: str):
        self.model.load_state_dict(torch.load(filepath, map_location="cpu", weights_only=True))
        self.fitted = True
