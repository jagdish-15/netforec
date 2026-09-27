"""
model.py
--------
The Temporal Transformer architecture for the new world model.
Reconstructed to match the state dict provided by the ML team.
"""

from __future__ import annotations

import torch
import torch.nn as nn

class Encoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(30, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, 32)
        )
    def forward(self, x): return self.net(x)

class Dynamics(nn.Module):
    def __init__(self):
        super().__init__()
        self.pos_embed = nn.Parameter(torch.zeros(1, 100, 32))
        layer = nn.TransformerEncoderLayer(d_model=32, nhead=4, dim_feedforward=128, batch_first=True)
        self.transformer = nn.TransformerEncoder(layer, num_layers=2)
    def forward(self, x):
        seq_len = x.size(1)
        x = x + self.pos_embed[:, :seq_len, :]
        return self.transformer(x)

class Predictor(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(64, 64),
            nn.ReLU(),
            nn.Linear(64, 32)
        )
    def forward(self, x): return self.net(x)

class StageHead(nn.Module):
    def __init__(self):
        super().__init__()
        # Outputs probabilities for the 4 classes
        self.net = nn.Sequential(
            nn.Linear(32, 32),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(32, 4)
        )
    def forward(self, x): return self.net(x)

class RatioHead(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 1)
        )
    def forward(self, x): return self.net(x)

class TemporalTransformer(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = Encoder()
        self.dynamics = Dynamics()
        self.predictor = Predictor()
        self.stage_head = StageHead()
        self.ratio_head = RatioHead()
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x is (B, seq_len, 30)
        e = self.encoder(x)
        h = self.dynamics(e)
        p = self.predictor(h)
        # return logits of the last timestep
        logits = self.stage_head(p[:, -1, :])
        return logits
