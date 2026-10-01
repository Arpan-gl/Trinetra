"""
PassiveSentinel - Layer L5c: DNS Model (DGA & Tunnelling Detector)
Combines:
1. Character-level CNN in PyTorch over domain string:
   - Embedding 32, Conv widths 3/4/5 with 64 filters each, Global Max-Pool, Dense 64, Dropout 0.2
2. Lexical & Behavioral LightGBM model:
   - Shannon entropy, length, digit ratio, consonant runs, n-gram log-likelihood
"""

import os
import torch
import torch.nn as nn
import numpy as np
import lightgbm as lgb
from typing import Dict, Any, Tuple, List

class CharCNN(nn.Module):
    def __init__(self, vocab_size: int = 128, embed_dim: int = 32, 
                 filters: int = 64, kernel_sizes: List[int] = [3, 4, 5], dense_dim: int = 64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.convs = nn.ModuleList([
            nn.Conv1d(in_channels=embed_dim, out_channels=filters, kernel_size=k)
            for k in kernel_sizes
        ])
        self.dropout = nn.Dropout(0.2)
        self.fc = nn.Sequential(
            nn.Linear(filters * len(kernel_sizes), dense_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(dense_dim, 2)  # Binary: 0=benign, 1=DGA
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch_size, seq_len)
        emb = self.embedding(x).transpose(1, 2)  # (batch, embed_dim, seq_len)
        pooled_outputs = []
        for conv in self.convs:
            c = torch.relu(conv(emb))
            p = torch.max(c, dim=2)[0]  # Global max pool
            pooled_outputs.append(p)
        cat = torch.cat(pooled_outputs, dim=1)
        drop = self.dropout(cat)
        out = self.fc(drop)
        return out

class DNSDetectorL5c:
    def __init__(self):
        self.char_cnn = CharCNN()
        self.lexical_gbm = lgb.LGBMClassifier(
            n_estimators=200, max_depth=5, learning_rate=0.05,
            random_state=42, n_jobs=2, verbose=-1
        )
        self.fitted = False

    @staticmethod
    def encode_domain(domain: str, max_len: int = 64) -> np.ndarray:
        clean = domain.strip().lower()[:max_len]
        chars = [min(127, ord(c)) for c in clean]
        padded = chars + [0] * (max_len - len(chars))
        return np.array(padded, dtype=np.int64)

    def train_char_cnn(self, domains: List[str], labels: np.ndarray, epochs: int = 8, batch_size: int = 128):
        print("Training L5c Character-level CNN...")
        encoded = np.array([self.encode_domain(d) for d in domains])
        tx = torch.tensor(encoded, dtype=torch.long)
        ty = torch.tensor(labels, dtype=torch.long)
        dataset = torch.utils.data.TensorDataset(tx, ty)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        optimizer = torch.optim.AdamW(self.char_cnn.parameters(), lr=1e-3, weight_decay=1e-2)
        criterion = nn.CrossEntropyLoss()

        self.char_cnn.train()
        for epoch in range(epochs):
            for bx, by in loader:
                optimizer.zero_grad()
                out = self.char_cnn(bx)
                loss = criterion(out, by)
                loss.backward()
                optimizer.step()

    def train_lexical_gbm(self, X_train: np.ndarray, y_train: np.ndarray):
        print("Training L5c Lexical-Behavioral LightGBM...")
        self.lexical_gbm.fit(X_train, y_train)
        self.fitted = True

    def predict_dga_score(self, domains: List[str], lexical_features: np.ndarray) -> np.ndarray:
        self.char_cnn.eval()
        with torch.no_grad():
            enc = np.array([self.encode_domain(d) for d in domains])
            tx = torch.tensor(enc, dtype=torch.long)
            cnn_logits = self.char_cnn(tx)
            cnn_probs = torch.softmax(cnn_logits, dim=-1)[:, 1].cpu().numpy()

        gbm_probs = self.lexical_gbm.predict_proba(lexical_features)[:, 1] if self.fitted else cnn_probs
        # Fused probability
        final_probs = 0.5 * cnn_probs + 0.5 * gbm_probs
        return final_probs

    def save(self, dirpath: str):
        os.makedirs(dirpath, exist_ok=True)
        torch.save(self.char_cnn.state_dict(), os.path.join(dirpath, "char_cnn.pt"))
        if self.fitted:
            with open(os.path.join(dirpath, "lexical_gbm.pkl"), "wb") as f:
                import pickle
                pickle.dump(self.lexical_gbm, f)

    def load(self, dirpath: str):
        self.char_cnn.load_state_dict(torch.load(os.path.join(dirpath, "char_cnn.pt"), map_location="cpu", weights_only=True))
        gbm_p = os.path.join(dirpath, "lexical_gbm.pkl")
        if os.path.exists(gbm_p):
            with open(gbm_p, "rb") as f:
                import pickle
                self.lexical_gbm = pickle.load(f)
            self.fitted = True
