"""
model.py
--------
The NETFORECLSTM architecture, copied verbatim from the ML team's training
notebook (`Final_preprocessed_dataset__3_.ipynb`) so `torch.load` state_dict
can be applied to a freshly constructed instance of the same class.

Do NOT change this architecture without also getting an updated
`netforc_lstm.pth` from the ML team — the layer shapes must match the
saved weights exactly or `load_state_dict` will fail.
"""

from __future__ import annotations

import torch
import torch.nn as nn


class NETFORECLSTM(nn.Module):
    def __init__(
        self,
        input_size: int = 16,
        hidden_size: int = 64,
        num_layers: int = 2,
        num_classes: int = 7,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout,
        )
        self.fc = nn.Linear(hidden_size, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out, (h, c) = self.lstm(x)
        return self.fc(out[:, -1, :])
