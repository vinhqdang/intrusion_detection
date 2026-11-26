"""Small conditional tabular GAN (torch) with optional attention, plus an MC-dropout filter.

Features are expected to be min-max scaled to [0, 1]; the generator ends in a sigmoid.
"""

from __future__ import annotations

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn

Z_DIM = 32
HIDDEN = 128
N_TOKENS = 8
N_HEADS = 4
BATCH = 256
LR = 2e-4
LAMBDA_AUX = 1.0
MAX_TRAIN_ROWS = 50_000


class Generator(nn.Module):
    """z (32) + one-hot label -> 128 -> [optional 8-token self-attention] -> 128 -> d (sigmoid)."""

    def __init__(self, n_classes: int, d: int, use_attention: bool = True) -> None:
        super().__init__()
        self.n_classes = n_classes
        self.use_attention = use_attention
        self.fc1 = nn.Linear(Z_DIM + n_classes, HIDDEN)
        if use_attention:
            self.attn = nn.MultiheadAttention(HIDDEN // N_TOKENS, N_HEADS, batch_first=True)
        self.fc2 = nn.Linear(HIDDEN, HIDDEN)
        self.out = nn.Linear(HIDDEN, d)

    def forward(self, z: torch.Tensor, y_onehot: torch.Tensor) -> torch.Tensor:
        h = torch.relu(self.fc1(torch.cat([z, y_onehot], dim=1)))
        if self.use_attention:
            tokens = h.view(h.shape[0], N_TOKENS, HIDDEN // N_TOKENS)
            attn, _ = self.attn(tokens, tokens, tokens, need_weights=False)
            h = (tokens + attn).reshape(h.shape[0], HIDDEN)
        h = torch.relu(self.fc2(h))
        return torch.sigmoid(self.out(h))


class Discriminator(nn.Module):
    """Label-conditioned MLP with an adversarial head and an auxiliary class head."""

    def __init__(self, n_classes: int, d: int) -> None:
        super().__init__()
        self.body = nn.Sequential(
            nn.Linear(d + n_classes, HIDDEN), nn.LeakyReLU(0.2), nn.Dropout(0.3),
            nn.Linear(HIDDEN, HIDDEN), nn.LeakyReLU(0.2), nn.Dropout(0.3),
        )
        self.adv = nn.Linear(HIDDEN, 1)
        self.aux = nn.Linear(HIDDEN, n_classes)

    def forward(self, x: torch.Tensor, y_onehot: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        h = self.body(torch.cat([x, y_onehot], dim=1))
        return self.adv(h).squeeze(1), self.aux(h)


def _stratified_cap(y_idx: np.ndarray, max_rows: int, rng: np.random.Generator) -> np.ndarray:
    n = len(y_idx)
    if n <= max_rows:
        return np.arange(n)
    keep = []
    for cls in np.unique(y_idx):
        idx = np.flatnonzero(y_idx == cls)
        quota = min(len(idx), max(1, int(round(max_rows * len(idx) / n))))
        keep.append(rng.choice(idx, size=quota, replace=False))
    return np.concatenate(keep)


def train_cgan(X: np.ndarray, y_idx: np.ndarray, n_classes: int, epochs: int = 50, seed: int = 0,
               use_attention: bool = True, lam: float = LAMBDA_AUX, batch: int = BATCH,
               lr: float = LR, max_rows: int = MAX_TRAIN_ROWS) -> tuple[Generator, dict]:
    """Train the conditional GAN with class-balanced real batches. Labels are 0..n_classes-1.

    The discriminator's auxiliary head is trained on real rows; the generator is penalised
    (weight ``lam``) when its auxiliary prediction disagrees with the conditioning label.
    """
    rng = np.random.default_rng(seed)
    torch.manual_seed(seed)
    keep = _stratified_cap(y_idx, max_rows, rng)
    order = np.argsort(y_idx[keep], kind="stable")
    rows = keep[order]
    Xt = torch.as_tensor(X[rows], dtype=torch.float32)
    ys = y_idx[rows]
    cls_list = np.unique(ys)
    starts = np.searchsorted(ys, cls_list)
    cnts = np.bincount(ys, minlength=n_classes)[cls_list]

    d = X.shape[1]
    G = Generator(n_classes, d, use_attention)
    D = Discriminator(n_classes, d)
    optG = torch.optim.Adam(G.parameters(), lr=lr, betas=(0.5, 0.999))
    optD = torch.optim.Adam(D.parameters(), lr=lr, betas=(0.5, 0.999))
    bce = nn.BCEWithLogitsLoss()
    ce = nn.CrossEntropyLoss()
    steps_per_epoch = max(1, len(rows) // batch)
    last = {"lossD": float("nan"), "lossG": float("nan")}
    G.train()
    D.train()
    for _ in range(epochs):
        for _ in range(steps_per_epoch):
            cls_pos = rng.integers(0, len(cls_list), batch)
            pos = starts[cls_pos] + (rng.random(batch) * cnts[cls_pos]).astype(int)
            xb = Xt[pos]
            yb = torch.as_tensor(cls_list[cls_pos], dtype=torch.long)
            oh = F.one_hot(yb, n_classes).float()
            z = torch.randn(batch, Z_DIM)
            fake = G(z, oh)
            ones = torch.ones(batch)
            zeros = torch.zeros(batch)
            d_real, a_real = D(xb, oh)
            d_fake, _ = D(fake.detach(), oh)
            loss_d = bce(d_real, ones) + bce(d_fake, zeros) + lam * ce(a_real, yb)
            optD.zero_grad()
            loss_d.backward()
            optD.step()
            d_fake2, a_fake = D(fake, oh)
            loss_g = bce(d_fake2, ones) + lam * ce(a_fake, yb)
            optG.zero_grad()
            loss_g.backward()
            optG.step()
            last = {"lossD": float(loss_d.detach()), "lossG": float(loss_g.detach())}
    G.eval()
    info = {"epochs": epochs, "steps": epochs * steps_per_epoch, "train_rows": int(len(rows)),
            **last}
    return G, info


def generate(G: Generator, gen_counts: dict[int, int], n_classes: int,
             seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """Sample gen_counts[c] synthetic rows for each class index c."""
    torch.manual_seed(seed + 1)
    d = G.out.out_features
    Xs, ys = [], []
    with torch.no_grad():
        for cls, n in gen_counts.items():
            if n <= 0:
                continue
            yc = torch.full((n,), int(cls), dtype=torch.long)
            Xs.append(G(torch.randn(n, Z_DIM), F.one_hot(yc, n_classes).float()).numpy())
            ys.append(np.full(n, int(cls), dtype=int))
    if not Xs:
        return np.empty((0, d)), np.empty(0, dtype=int)
    return np.vstack(Xs).astype(np.float64), np.concatenate(ys)


class _MCNet(nn.Module):
    def __init__(self, d: int, n_classes: int, p: float) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(d, 128), nn.ReLU(), nn.Dropout(p),
            nn.Linear(128, 128), nn.ReLU(), nn.Dropout(p),
            nn.Linear(128, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


def mc_dropout_filter(X_syn: np.ndarray, y_syn: np.ndarray, X_real: np.ndarray, y_real: np.ndarray,
                      T: int = 20, seed: int = 0, rule: str = "lite_gen", p: float = 0.3,
                      epochs: int = 5, batch: int = 256, lr: float = 1e-3
                      ) -> tuple[np.ndarray, dict]:
    """Keep reliable synthetic rows using Monte-Carlo dropout uncertainty.

    An MLP with dropout p is trained for ``epochs`` on the real rows. For each synthetic row,
    T stochastic forward passes give probabilities p_t; Var = mean_t ||p_t - p_bar||^2.
    Rules:
      "lite_gen": keep rows with |Var - mean(Var)| <= std(Var)  (LITE-GEN rule, population std)
      "low_var":  keep rows with Var <= mean(Var) and argmax(p_bar) == y
    Labels must be integers 0..K-1. Returns (boolean mask over X_syn, stats dict).
    """
    if rule not in ("lite_gen", "low_var"):
        raise ValueError(f"rule must be 'lite_gen' or 'low_var', got {rule!r}")
    X_syn = np.asarray(X_syn, dtype=np.float32)
    y_syn = np.asarray(y_syn, dtype=int)
    n = len(X_syn)
    if n == 0:
        return np.zeros(0, dtype=bool), {"rule": rule, "n_candidates": 0, "n_kept": 0,
                                         "kept_fraction": float("nan")}
    X_real = np.asarray(X_real, dtype=np.float32)
    y_real = np.asarray(y_real, dtype=int)
    n_classes = int(max(y_real.max(), y_syn.max())) + 1
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    net = _MCNet(X_real.shape[1], n_classes, p)
    opt = torch.optim.Adam(net.parameters(), lr=lr)
    ce = nn.CrossEntropyLoss()
    Xr = torch.as_tensor(X_real)
    yr = torch.as_tensor(y_real, dtype=torch.long)
    net.train()
    for _ in range(epochs):
        perm = torch.as_tensor(rng.permutation(len(Xr)))
        for i in range(0, len(Xr), batch):
            idx = perm[i:i + batch]
            loss = ce(net(Xr[idx]), yr[idx])
            opt.zero_grad()
            loss.backward()
            opt.step()
    net.train()  # keep dropout active for Monte-Carlo passes
    Xs = torch.as_tensor(X_syn)
    passes = []
    with torch.no_grad():
        for _ in range(T):
            passes.append(torch.softmax(net(Xs), dim=1).numpy())
    P = np.stack(passes)                      # (T, N, K)
    p_bar = P.mean(axis=0)
    var = ((P - p_bar[None]) ** 2).sum(axis=2).mean(axis=0)
    if rule == "lite_gen":
        mu, sd = var.mean(), var.std()
        mask = np.abs(var - mu) <= sd
    else:
        mask = (var <= var.mean()) & (p_bar.argmax(axis=1) == y_syn)
    stats = {"rule": rule, "n_candidates": int(n), "n_kept": int(mask.sum()),
             "kept_fraction": float(mask.mean()), "var_mean": float(var.mean()),
             "var_std": float(var.std())}
    return mask, stats


def augment(X: np.ndarray, y_idx: np.ndarray, n_classes: int, gen_counts: dict[int, int],
            epochs: int = 50, seed: int = 0, mc_filter: bool = False, rule: str = "lite_gen",
            T: int = 20, use_attention: bool = True) -> tuple[np.ndarray, np.ndarray, dict]:
    """Train a cGAN on real rows, generate gen_counts, optionally MC-filter them."""
    G, info = train_cgan(X, y_idx, n_classes, epochs=epochs, seed=seed,
                         use_attention=use_attention)
    Xs, ys = generate(G, gen_counts, n_classes, seed=seed)
    stats: dict = {"n_generated": int(len(ys)), "gan": info}
    if mc_filter and len(ys):
        mask, fstats = mc_dropout_filter(Xs, ys, X, y_idx, T=T, seed=seed, rule=rule)
        Xs, ys = Xs[mask], ys[mask]
        stats["mc_filter"] = fstats
    stats["n_kept"] = int(len(ys))
    return Xs, ys, stats


class CGANSampler:
    """Oversample every non-majority class with the cGAN, up to the majority count (capped)."""

    def __init__(self, seed: int = 0, epochs: int = 50, max_per_class: int = 20000,
                 mc_filter: bool = False, filter_rule: str = "lite_gen", T: int = 20) -> None:
        self.seed = seed
        self.epochs = epochs
        self.max_per_class = max_per_class
        self.mc_filter = mc_filter
        self.filter_rule = filter_rule
        self.T = T
        self.stats_: dict = {}

    def fit_resample(self, X: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y)
        classes, y_idx = np.unique(y, return_inverse=True)
        counts = np.bincount(y_idx, minlength=len(classes))
        maj = counts.max()
        gen = {c: min(int(maj - counts[c]), self.max_per_class)
               for c in range(len(classes)) if counts[c] < maj}
        if not gen:
            return X.copy(), y.copy()
        Xs, ys, self.stats_ = augment(X, y_idx, len(classes), gen, epochs=self.epochs,
                                      seed=self.seed, mc_filter=self.mc_filter,
                                      rule=self.filter_rule, T=self.T)
        return np.vstack([X, Xs]), np.concatenate([y, classes[ys]]) if len(ys) else y.copy()
