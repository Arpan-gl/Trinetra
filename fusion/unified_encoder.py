"""
PassiveSentinel - Layer L6 & L7: Unified Encoder with Typed Heads & Calibration
Inspired by System One multi-task decision architectures:
1. Input: T=64 tokens (up to 63 flow tokens + 1 expert-score token from L5a..L5e)
2. Continuous-time log(IAT) encoding + linear projection to d_model=64
3. N=2 bidirectional self-attention layers with RMSNorm, SwiGLU feed-forward (d_ff=256), 4 heads
4. Parallel cross-attention query pooling over typed questions:
   - Boolean head (sigmoid): is_malicious, is_spoofed, is_periodic, is_encrypted_threat
   - Choice head (softmax): 7-way threat class distribution + confidence
   - Score head (expectation over K=11 bins): severity in [0, 10]
5. L7 Temperature scaling calibration + evidence-aware fusion
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, Any, Tuple, Optional

class RMSNorm(nn.Module):
    def __init__(self, d_model: int, eps: float = 1e-6):
        super().__init__()
        self.eps = eps
        self.scale = nn.Parameter(torch.ones(d_model))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        variance = x.pow(2).mean(-1, keepdim=True)
        return x * torch.rsqrt(variance + self.eps) * self.scale

class SwiGLU(nn.Module):
    def __init__(self, d_model: int, d_ff: int = 256):
        super().__init__()
        self.w1 = nn.Linear(d_model, d_ff, bias=False)
        self.w2 = nn.Linear(d_ff, d_model, bias=False)
        self.w3 = nn.Linear(d_model, d_ff, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.w2(F.silu(self.w1(x)) * self.w3(x))

class TransformerBlock(nn.Module):
    def __init__(self, d_model: int = 64, n_heads: int = 4, d_ff: int = 256, dropout: float = 0.1):
        super().__init__()
        self.norm1 = RMSNorm(d_model)
        self.attn = nn.MultiheadAttention(d_model, n_heads, dropout=dropout, batch_first=True)
        self.norm2 = RMSNorm(d_model)
        self.ffn = SwiGLU(d_model, d_ff)
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        norm_x = self.norm1(x)
        attn_out, _ = self.attn(norm_x, norm_x, norm_x)
        x = x + self.drop(attn_out)
        x = x + self.drop(self.ffn(self.norm2(x)))
        return x

class UnifiedEncoderL6(nn.Module):
    def __init__(self, in_features: int = 16, d_model: int = 64, n_layers: int = 2, 
                 n_heads: int = 4, d_ff: int = 256, n_classes: int = 7, k_bins: int = 11):
        super().__init__()
        self.d_model = d_model
        self.token_proj = nn.Linear(in_features, d_model)
        
        # N=2 encoder layers
        self.layers = nn.ModuleList([
            TransformerBlock(d_model, n_heads, d_ff) for _ in range(n_layers)
        ])
        self.final_norm = RMSNorm(d_model)

        # Typed question embeddings: 0=Boolean, 1=Choice, 2=Score
        self.question_pool = nn.Embedding(3, d_model)
        self.cross_attn = nn.MultiheadAttention(d_model, n_heads, batch_first=True)

        # Typed heads
        self.bool_head = nn.Linear(d_model, 4)      # 4 boolean questions
        self.choice_head = nn.Linear(d_model, n_classes) # 7-way threat class
        self.score_head = nn.Linear(d_model, k_bins)     # 11 bins for severity expectation

        # L7 calibration temperature parameter
        self.temperature = nn.Parameter(torch.ones(1), requires_grad=False)

    def compute_continuous_time_encoding(self, delta_t: torch.Tensor) -> torch.Tensor:
        """
        Sinusoidal Fourier temporal embedding over log(1 + delta_t).
        """
        half_dim = self.d_model // 2
        freqs = torch.exp(torch.arange(half_dim, device=delta_t.device) * -(math.log(10000.0) / (half_dim - 1)))
        log_dt = torch.log1p(torch.clamp(delta_t, min=0.0)).unsqueeze(-1)
        args = log_dt * freqs.unsqueeze(0).unsqueeze(0)
        pe = torch.cat([torch.sin(args), torch.cos(args)], dim=-1)
        return pe

    def forward(self, tokens: torch.Tensor, delta_t: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        # tokens: (batch, seq_len=64, in_features)
        h = self.token_proj(tokens)
        if delta_t is not None:
            pe = self.compute_continuous_time_encoding(delta_t)
            h = h + pe

        # Bidirectional self-attention
        for layer in self.layers:
            h = layer(h)
        h = self.final_norm(h)  # Contextual memory H: (batch, seq_len, d_model)

        # Cross-attention with question pool
        batch_size = tokens.size(0)
        # q: (batch, 3, d_model)
        q = self.question_pool.weight.unsqueeze(0).expand(batch_size, -1, -1)
        pooled, _ = self.cross_attn(q, h, h)  # (batch, 3, d_model)

        z_bool = pooled[:, 0, :]
        z_choice = pooled[:, 1, :]
        z_score = pooled[:, 2, :]

        # Emit typed head outputs
        bool_probs = torch.sigmoid(self.bool_head(z_bool))
        choice_logits = self.choice_head(z_choice) / torch.clamp(self.temperature, min=0.1)
        
        # Score expectation over K=11 bins: expectation = sum_k (k * p_k)
        score_bin_probs = torch.softmax(self.score_head(z_score), dim=-1)
        bins = torch.arange(11, dtype=torch.float32, device=tokens.device)
        score_expectation = torch.sum(score_bin_probs * bins, dim=-1)

        return choice_logits, bool_probs, score_expectation, score_bin_probs

class FocalLoss(nn.Module):
    def __init__(self, gamma: float = 2.0, class_weights: Optional[torch.Tensor] = None, label_smoothing: float = 0.05):
        super().__init__()
        self.gamma = gamma
        self.class_weights = class_weights
        self.smoothing = label_smoothing

    def forward(self, logits: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        ce = F.cross_entropy(logits, target, weight=self.class_weights, label_smoothing=self.smoothing, reduction="none")
        pt = torch.exp(-ce)
        focal_loss = ((1.0 - pt) ** self.gamma) * ce
        return focal_loss.mean()

class TemperatureScalerL7:
    """Fits post-hoc temperature scaling on validation logits to minimize NLL and ECE."""
    @staticmethod
    def fit_temperature(logits: np.ndarray, labels: np.ndarray) -> float:
        t_logits = torch.tensor(logits, dtype=torch.float32)
        t_labels = torch.tensor(labels, dtype=torch.long)
        
        temp = nn.Parameter(torch.ones(1) * 1.5)
        optimizer = torch.optim.LBFGS([temp], lr=0.01, max_iter=50)

        def eval_step():
            optimizer.zero_grad()
            loss = F.cross_entropy(t_logits / torch.clamp(temp, min=0.1), t_labels)
            loss.backward()
            return loss

        optimizer.step(eval_step)
        fitted_t = float(torch.clamp(temp, min=0.2, max=5.0).item())
        print(f"L7 Temperature scaling fitted: T = {fitted_t:.4f}")
        return fitted_t
