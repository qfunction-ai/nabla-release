"""GCN-LOF hybrid anomaly detection — relational scoring on a KNN graph.

Implements the approach from Qin et al. (Computer Networks 2025):
1. Feature extraction — log entries → numerical vectors
2. Graph construction — KNN graph on feature vectors
3. LOF enrichment — Local Outlier Factor scores as node features
4. GCN forward pass — 2-layer GCN with self-supervised reconstruction
5. Anomaly scoring — combined LOF + reconstruction error

No GPU needed. Pure numpy/scipy. Graphs are small (100-500 nodes per batch).
"""

import json
import os
from collections import defaultdict

import numpy as np
from scipy.sparse import csr_matrix, lil_matrix, eye
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from nabla.log import get_logger
from nabla.utils import is_off_hours

logger = get_logger("gcn_lof")

# --- Feature dimensions ---
# One-hot: log_type (4) + action_type (8) = 12
# Binary: is_off_hours, is_lolbin, is_suspicious_parent, is_critical_host,
#         is_pre_flagged, has_suspicious_cmd = 6
# Continuous: hour_sin, hour_cos, num_unique_ips, event_count_zscore,
#            auth_failure_ratio = 5
# + LOF score = 1
# Total: 24 features (23 input + 1 LOF)

LOG_TYPES = ["auth", "network", "dns", "endpoint"]
ACTION_TYPES = [
    "login_success", "login_failure", "privilege_escalation", "account_lockout",
    "execute", "modify", "create", "delete",
]
# Other actions (query, connect, etc.) get all zeros in the action one-hot

# LOLBIN process names for binary feature
LOLBIN_PROCESSES = {
    "certutil", "mshta", "wscript", "cscript", "regsvr32",
    "rundll32", "bitsadmin", "powershell", "wmic",
}

# Suspicious parent processes for binary feature
SUSPICIOUS_PARENTS = {
    "winword", "excel", "powerpnt", "outlook",
    "acrobat", "reader", "chrome", "firefox",
    "thunderbird", "acrord32",
}

# Suspicious command-line patterns for binary feature
SUSPICIOUS_CMD_PATTERNS = [
    "http://", "https://", "-enc", "-encodedcommand", "iex",
    "invoke-expression", "-w hidden", "frombase64string",
    "urlcache", "download", "scrobj.dll", "/i:http",
    "javascript:", "bypass", "noprofile", "base64",
]

# Critical host name patterns
CRITICAL_HOST_PATTERNS = ["DC", "DOMAIN", "BUILD", "PROD", "FINANCE", "SERVER"]


def _one_hot(value: str, categories: list[str]) -> list[float]:
    """Encode a value as a one-hot vector.

    Args:
        value: The value to encode.
        categories: List of category names.

    Returns:
        One-hot vector with 1.0 at the matching index, 0.0 elsewhere.
    """
    vec = [0.0] * len(categories)
    try:
        vec[categories.index(value)] = 1.0
    except ValueError:
        pass  # silent by design: unknown category encodes as all zeros (2026-09 sweep)
    return vec


def _extract_features(
    entries: list[dict],
    _baselines: dict | None = None,
) -> np.ndarray:
    """Convert log entries into a numerical feature matrix.

    Args:
        entries: List of log entry dicts.
        _baselines: (Unused — features are computed from entries directly)

    Returns:
        NumPy array of shape (n_entries, 23) with feature vectors.
    """
    if not entries:
        return np.zeros((0, 23))

    # Pre-compute per-user stats from entries (if no baselines provided)
    user_event_counts = defaultdict(int)
    user_ip_counts = defaultdict(set)
    user_auth = defaultdict(lambda: {"success": 0, "failure": 0})

    for e in entries:
        user = e.get("user", e.get("src_ip", e.get("client_ip", "unknown")))
        user_event_counts[user] += 1
        ip = e.get("source_ip", e.get("src_ip", e.get("client_ip", "")))
        if ip:
            user_ip_counts[user].add(ip)
        action = e.get("action", "")
        if action == "login_success":
            user_auth[user]["success"] += 1
        elif action == "login_failure":
            user_auth[user]["failure"] += 1

    # Global stats for z-score normalization
    counts = list(user_event_counts.values())
    if len(counts) >= 2:
        mean_count = sum(counts) / len(counts)
        variance = sum((c - mean_count) ** 2 for c in counts) / len(counts)
        std_count = variance ** 0.5 if variance > 0 else 0.01
    else:
        mean_count = sum(counts) if counts else 0
        std_count = 0.01

    features = []
    for e in entries:
        log_type = e.get("type", "unknown")
        action = e.get("action", "")
        user = e.get("user", e.get("src_ip", e.get("client_ip", "unknown")))
        ts = e.get("timestamp", "")
        proc = (e.get("process", "") or e.get("Image", "") or "").lower().replace(".exe", "")
        parent = (e.get("parent_process", "") or e.get("ParentImage", "") or "").lower().replace(".exe", "")
        cmd = (e.get("command_line", "") or e.get("CommandLine", "") or "").lower()
        host = (e.get("host", "") or e.get("Computer", "") or "").upper()

        # 1. Log type one-hot (4 dims)
        type_vec = _one_hot(log_type, LOG_TYPES)

        # 2. Action type one-hot (8 dims)
        action_vec = _one_hot(action, ACTION_TYPES)

        # 3. Cyclical hour encoding (2 dims)
        hour_sin, hour_cos = 0.0, 0.0
        if ts:
            try:
                from nabla.utils import _parse_hour
                hour = _parse_hour(ts)
                rad = 2 * np.pi * hour / 24
                hour_sin = np.sin(rad)
                hour_cos = np.cos(rad)
            except (ValueError, IndexError):
                pass  # silent by design: malformed feature extraction input (2026-09 sweep)

        # 4. Binary features (6 dims)
        is_off_hours_val = 1.0 if is_off_hours(ts) else 0.0

        is_lolbin = 1.0 if any(lol in proc for lol in LOLBIN_PROCESSES) else 0.0
        is_suspicious_parent = 1.0 if parent in SUSPICIOUS_PARENTS else 0.0
        is_critical_host = 1.0 if any(p in host for p in CRITICAL_HOST_PATTERNS) else 0.0
        # A13: the rule VERDICT does not feed the graph — including it
        # double-counts rule hits (the GCN re-learns what rules decided);
        # content signatures above stay, verdicts go
        is_pre_flagged = 0.0
        has_suspicious_cmd = 1.0 if any(p in cmd for p in SUSPICIOUS_CMD_PATTERNS) else 0.0

        # 5. Continuous features (3 dims)
        num_unique_ips = len(user_ip_counts.get(user, set()))
        # Normalize by max in batch
        max_ips = max(len(ips) for ips in user_ip_counts.values()) if user_ip_counts else 1
        norm_ips = num_unique_ips / max_ips if max_ips > 0 else 0.0

        event_count = user_event_counts.get(user, 0)
        z_score = (event_count - mean_count) / std_count if std_count > 0 else 0.0
        # Clip z-score to [-5, 5] for numerical stability
        z_score = max(-5.0, min(5.0, z_score))
        norm_zscore = z_score / 5.0  # Normalize to [-1, 1]

        total_auth = user_auth[user]["success"] + user_auth[user]["failure"]
        auth_failure_ratio = user_auth[user]["failure"] / total_auth if total_auth > 0 else 0.0

        # Assemble feature vector (23 dims)
        vec = (
            type_vec          # 4
            + action_vec      # 8
            + [hour_sin, hour_cos]  # 2
            + [is_off_hours_val, is_lolbin, is_suspicious_parent,
               is_critical_host, is_pre_flagged, has_suspicious_cmd]  # 6
            + [norm_ips, norm_zscore, auth_failure_ratio]  # 3
        )
        features.append(vec)

    return np.array(features, dtype=np.float64)


def _build_knn_graph(
    features: np.ndarray,
    k: int = 10,
) -> csr_matrix:
    """Build a KNN adjacency matrix from feature vectors.

    Uses cosine similarity to find k nearest neighbors per node.
    Adds self-loops (standard GCN practice).

    Args:
        features: Feature matrix of shape (n, d).
        k: Number of nearest neighbors.

    Returns:
        Sparse adjacency matrix of shape (n, n).
    """
    n = features.shape[0]
    if n == 0:
        return csr_matrix((0, 0))

    # Normalize features for cosine similarity
    norms = np.linalg.norm(features, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)  # Avoid division by zero
    normed = features / norms

    # Compute cosine similarity matrix
    similarity = normed @ normed.T

    # For each node, keep top-k neighbors (excluding self)
    actual_k = min(k, n - 1)
    adj = lil_matrix((n, n), dtype=np.float64)

    for i in range(n):
        row = similarity[i].copy()
        row[i] = -np.inf  # Exclude self
        top_k = np.argsort(row)[-actual_k:]
        for j in top_k:
            if similarity[i, j] > 0:  # Only positive similarity
                adj[i, j] = 1.0
                adj[j, i] = 1.0  # Symmetric

    # Add self-loops
    adj = adj.tocsr()
    adj = adj + eye(n, format="csr")

    return adj


def _compute_lof_scores(features: np.ndarray, n_neighbors: int = 20) -> np.ndarray:
    """Compute Local Outlier Factor scores for each node.

    Args:
        features: Feature matrix of shape (n, d).
        n_neighbors: Number of neighbors for LOF computation.

    Returns:
        Array of LOF scores of shape (n,). Higher = more anomalous.
        LOF ≈ 1.0 means normal density; LOF >> 1.0 means outlier.
    """
    n = features.shape[0]
    if n < 2:
        return np.ones(n)

    actual_neighbors = min(n_neighbors, n - 1)
    if actual_neighbors < 2:
        return np.ones(n)

    lof = LocalOutlierFactor(n_neighbors=actual_neighbors, contamination="auto")
    lof.fit_predict(features)  # fit_predict computes the LOF scores
    # negative_outlier_factor_ is negative; higher (less negative) = more normal
    # Convert to positive scores where higher = more anomalous
    scores = -lof.negative_outlier_factor_
    return scores


def _normalize_scores(scores: np.ndarray) -> np.ndarray:
    """Min-max normalize scores to [0, 1].

    Args:
        scores: Raw scores array.

    Returns:
        Normalized scores in [0, 1]. Returns 0.5 if all scores are equal.
    """
    min_s = scores.min()
    max_s = scores.max()
    if max_s - min_s < 1e-10:
        return np.full_like(scores, 0.5)
    return (scores - min_s) / (max_s - min_s)


class GCNLayer:
    """Single Graph Convolutional Network layer.

    Implements: H' = σ(Â · H · W)
    where Â is the normalized adjacency matrix,
    H is the input feature matrix, and W is the weight matrix.

    Args:
        in_dim: Input feature dimension.
        out_dim: Output feature dimension.
    """

    def __init__(self, in_dim: int, out_dim: int):
        # Xavier initialization
        scale = np.sqrt(2.0 / (in_dim + out_dim))
        self.weights = np.random.randn(in_dim, out_dim) * scale
        self.bias = np.zeros(out_dim)

    def forward(self, features: np.ndarray, adj_norm: csr_matrix) -> np.ndarray:
        """Forward pass: Â · H · W + b.

        Args:
            features: Input features of shape (n, in_dim).
            adj_norm: Normalized adjacency matrix of shape (n, n).

        Returns:
            Output features of shape (n, out_dim).
        """
        # D^{-1/2} Â D^{-1/2} · H · W + b
        hidden = adj_norm.dot(features).dot(self.weights) + self.bias
        return hidden

    def get_params(self) -> dict:
        """Serialize layer parameters."""
        return {
            "weights": self.weights.tolist(),
            "bias": self.bias.tolist(),
        }

    def set_params(self, data: dict) -> None:
        """Deserialize layer parameters."""
        self.weights = np.array(data["weights"])
        self.bias = np.array(data["bias"])


def _normalize_adjacency(adj: csr_matrix) -> csr_matrix:
    """Compute D^{-1/2} Â D^{-1/2} for symmetric normalization.

    Args:
        adj: Sparse adjacency matrix with self-loops.

    Returns:
        Symmetrically normalized adjacency matrix.
    """
    degrees = np.array(adj.sum(axis=1)).flatten()
    degrees = np.where(degrees == 0, 1.0, degrees)  # Avoid division by zero
    d_inv_sqrt = 1.0 / np.sqrt(degrees)
    # D^{-1/2} as diagonal matrix
    d_inv_sqrt_mat = csr_matrix((d_inv_sqrt, (np.arange(len(d_inv_sqrt)), np.arange(len(d_inv_sqrt)))))
    return d_inv_sqrt_mat.dot(adj).dot(d_inv_sqrt_mat)


def _relu(x: np.ndarray) -> np.ndarray:
    """ReLU activation function."""
    return np.maximum(0, x)


class GCNLOFDetector:
    """GCN-LOF hybrid anomaly detector.

    Self-supervised: trained to reconstruct input features from
    GCN embeddings. High reconstruction error = anomaly.

    Args:
        input_dim: Number of input features (23 + 1 LOF = 24).
        hidden_dim: GCN hidden layer dimension.
        embed_dim: GCN output embedding dimension.
        k_neighbors: KNN graph k parameter.
        lof_neighbors: LOF n_neighbors parameter.
        alpha: Weight of LOF score in combined anomaly score (0-1).
        dropout_rate: Dropout rate for training (0-1).
    """

    def __init__(
        self,
        input_dim: int = 24,
        hidden_dim: int = 32,
        embed_dim: int = 16,
        k_neighbors: int = 10,
        lof_neighbors: int = 20,
        alpha: float = 0.5,
        dropout_rate: float = 0.3,
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.embed_dim = embed_dim
        self.score_bank: dict = {}  # A12: per-component Welford stats across runs
        self.k_neighbors = k_neighbors
        self.lof_neighbors = lof_neighbors
        self.alpha = alpha
        self.dropout_rate = dropout_rate

        # GCN encoder layers
        self.gcn1 = GCNLayer(input_dim, hidden_dim)
        self.gcn2 = GCNLayer(hidden_dim, embed_dim)

        # Reconstruction decoder (simple linear)
        self.decoder = GCNLayer(embed_dim, input_dim)

        # Feature scaler (fit on training data)
        self.scaler_mean: np.ndarray | None = None
        self.scaler_scale: np.ndarray | None = None

        # Training state
        self.train_epochs = 5
        self.learning_rate = 0.01

    def _scale_features(self, features: np.ndarray, fit: bool = False) -> np.ndarray:
        """Standardize features using StandardScaler.

        Args:
            features: Raw feature matrix.
            fit: If True, fit the scaler. If False, use existing scaler params.

        Returns:
            Standardized feature matrix.
        """
        if fit:
            scaler = StandardScaler()
            scaled = scaler.fit_transform(features)
            self.scaler_mean = scaler.mean_
            self.scaler_scale = scaler.scale_
            return scaled

        # Use stored scaler params
        if self.scaler_mean is not None and self.scaler_scale is not None:
            return (features - self.scaler_mean) / self.scaler_scale
        return features

    def _bank_zscore(self, raw: "np.ndarray", component: str) -> "np.ndarray":
        """Z-score raw scores against the persisted score bank (A12).

        The bank holds running mean/M2 (Welford) per component across runs.
        Order-of-operations note (round-6 S9 docstring fix): the code
        updates the bank FIRST and scores against the POST-update
        statistics — the pre-update claim here was wrong. Inert while
        GCN-LOF stays disabled (R3/N11); correct it before re-enabling.
        """
        bank = self.score_bank.setdefault(component, {"count": 0, "mean": 0.0, "m2": 0.0})
        # Welford update with this batch's values
        for v in raw:
            bank["count"] += 1
            delta = float(v) - bank["mean"]
            bank["mean"] += delta / bank["count"]
            bank["m2"] += delta * (float(v) - bank["mean"])
        # Score against the bank (current stats include this batch; with
        # enough history one batch barely moves them)
        n, mean, m2 = bank["count"], bank["mean"], bank["m2"]
        if n < 50 or m2 <= 0:
            return np.zeros_like(raw)  # not enough history: flag nothing
        std = (m2 / n) ** 0.5
        return (raw - mean) / std

    def _encode(self, features: np.ndarray, adj_norm: csr_matrix) -> np.ndarray:
        """GCN encoder: 2-layer GCN with ReLU.

        Args:
            features: Input features of shape (n, input_dim).
            adj_norm: Normalized adjacency matrix.

        Returns:
            Embeddings of shape (n, embed_dim).
        """
        h = self.gcn1.forward(features, adj_norm)
        h = _relu(h)
        h = self.gcn2.forward(h, adj_norm)
        return h

    def _reconstruct(self, embeddings: np.ndarray) -> np.ndarray:
        """Linear decoder: embeddings → reconstructed features.

        Args:
            embeddings: GCN embeddings of shape (n, embed_dim).

        Returns:
            Reconstructed features of shape (n, input_dim).
        """
        # decoder.weights is (embed_dim, input_dim), embeddings is (n, embed_dim)
        # Result: (n, embed_dim) dot (embed_dim, input_dim) = (n, input_dim)
        return embeddings.dot(self.decoder.weights) + self.decoder.bias

    def _compute_reconstruction_error(self, features: np.ndarray, reconstructed: np.ndarray) -> np.ndarray:
        """Compute per-node reconstruction error (MSE).

        Args:
            features: Original features.
            reconstructed: Reconstructed features.

        Returns:
            Per-node MSE of shape (n,).
        """
        return np.mean((features - reconstructed) ** 2, axis=1)

    def _train_step(
        self,
        features: np.ndarray,
        adj_norm: csr_matrix,
        lr: float,
    ) -> float:
        """Single training step: forward + backward + weight update.

        Uses gradient descent on reconstruction loss.
        Gradients computed manually (no autograd needed for 3 layers).

        Args:
            features: Input features.
            adj_norm: Normalized adjacency matrix.
            lr: Learning rate.

        Returns:
            Reconstruction loss (MSE).
        """
        n = features.shape[0]

        # Forward pass
        h1 = self.gcn1.forward(features, adj_norm)
        h1_act = _relu(h1)
        h2 = self.gcn2.forward(h1_act, adj_norm)
        reconstructed = self._reconstruct(h2)

        # Loss: MSE
        diff = reconstructed - features
        loss = np.mean(diff ** 2)

        # Backward pass (manual gradients)
        # d_loss/d_reconstructed = 2 * diff / n
        d_recon = 2.0 * diff / n  # (n, input_dim)

        # Decoder gradients
        # d_loss/d_decoder_weights = h2.T @ d_recon
        d_decoder_w = h2.T @ d_recon  # (embed_dim, input_dim)
        d_decoder_b = d_recon.mean(axis=0)  # (input_dim,)

        # d_loss/d_h2 = d_recon @ decoder_weights.T
        d_h2 = d_recon @ self.decoder.weights.T  # (n, embed_dim)

        # GCN2 gradients
        # d_loss/d_gcn2_weights = h1_act.T @ (adj_norm.T @ d_h2) ... simplified
        # For GCN: d_loss/d_W = H_in.T @ (A_norm^T @ d_out)
        d_gcn2_out = adj_norm.T.dot(d_h2)  # (n, embed_dim)
        d_gcn2_w = h1_act.T @ d_gcn2_out  # (hidden_dim, embed_dim)
        d_gcn2_b = d_h2.mean(axis=0)  # (embed_dim,)

        # d_loss/d_h1_act = (adj_norm.T @ d_h2) @ gcn2.weights.T
        d_h1_act = adj_norm.T.dot(d_h2) @ self.gcn2.weights.T  # (n, hidden_dim)

        # ReLU gradient: zero out where h1 < 0
        d_h1 = d_h1_act * (h1 > 0).astype(float)  # (n, hidden_dim)

        # GCN1 gradients
        d_gcn1_out = adj_norm.T.dot(d_h1)  # (n, hidden_dim)
        d_gcn1_w = features.T @ d_gcn1_out  # (input_dim, hidden_dim)
        d_gcn1_b = d_h1.mean(axis=0)  # (hidden_dim,)

        # Gradient clipping for stability
        max_grad = 5.0
        for grad in [d_gcn1_w, d_gcn1_b, d_gcn2_w, d_gcn2_b, d_decoder_w, d_decoder_b]:
            np.clip(grad, -max_grad, max_grad, out=grad)

        # Weight updates
        self.gcn1.weights -= lr * d_gcn1_w
        self.gcn1.bias -= lr * d_gcn1_b
        self.gcn2.weights -= lr * d_gcn2_w
        self.gcn2.bias -= lr * d_gcn2_b
        self.decoder.weights -= lr * d_decoder_w  # d_decoder_w is already (embed_dim, input_dim)
        self.decoder.bias -= lr * d_decoder_b

        return loss

    def train(
        self,
        features: np.ndarray,
        adj_norm: csr_matrix,
        epochs: int | None = None,
    ) -> list[float]:
        """Train the GCN autoencoder on a batch of events.

        Args:
            features: Scaled feature matrix.
            adj_norm: Normalized adjacency matrix.
            epochs: Number of training epochs. Uses self.train_epochs if None.

        Returns:
            List of loss values per epoch.
        """
        n_epochs = epochs or self.train_epochs
        losses = []

        for epoch in range(n_epochs):
            # Apply dropout to features (mask random entries)
            if self.dropout_rate > 0 and n_epochs > 1:
                mask = np.random.binomial(1, 1 - self.dropout_rate, features.shape)
                masked_features = features * mask
            else:
                masked_features = features

            loss = self._train_step(masked_features, adj_norm, self.learning_rate)
            losses.append(loss)

            if np.isnan(loss) or np.isinf(loss):
                logger.warning("NaN/Inf loss at epoch %d, stopping training", epoch)
                break

        return losses

    def detect(
        self,
        entries: list[dict],
        baselines: dict | None = None,
        threshold: float = 0.75,
        _existing_anomalies: list[dict] | None = None,
    ) -> list[dict]:
        """Run GCN-LOF detection on a batch of log entries.

        Args:
            entries: List of log entry dicts.
            baselines: Optional baseline dict for feature extraction.
            threshold: Anomaly score threshold (0-1). Events scoring above
                       this are flagged as anomalies.
            existing_anomalies: Anomalies from other detection methods.
                                Used to set is_pre_flagged feature.

        Returns:
            List of anomaly dicts with detection_method="gcn_lof".
        """
        if len(entries) < 3:
            logger.debug("Too few entries (%d) for GCN-LOF, skipping", len(entries))
            return []

        # Step 1: Extract features
        raw_features = _extract_features(entries, baselines)
        if raw_features.shape[0] == 0:
            return []

        # Step 2: Scale features (fit on first run, transform on subsequent)
        is_first_run = self.scaler_mean is None
        features = self._scale_features(raw_features, fit=is_first_run)

        # Step 3: Compute LOF scores
        lof_scores = _compute_lof_scores(features, n_neighbors=self.lof_neighbors)
        norm_lof = _normalize_scores(lof_scores)

        # Step 4: Append LOF score as feature dimension
        features_with_lof = np.hstack([features, norm_lof.reshape(-1, 1)])

        # Adjust input dim if first run (23 + 1 LOF = 24)
        if is_first_run and self.input_dim != features_with_lof.shape[1]:
            old_weights = self.gcn1.weights
            old_bias = self.gcn1.bias
            self.gcn1 = GCNLayer(features_with_lof.shape[1], self.hidden_dim)
            # Copy over existing weights for the first 23 dims
            min_dim = min(old_weights.shape[0], features_with_lof.shape[1])
            self.gcn1.weights[:min_dim] = old_weights[:min_dim]
            self.gcn1.bias = old_bias
            self.input_dim = features_with_lof.shape[1]
            # Also update decoder output dim
            self.decoder = GCNLayer(self.embed_dim, self.input_dim)

        # Step 5: Build KNN graph
        actual_k = min(self.k_neighbors, len(entries) - 1)
        adj = _build_knn_graph(features_with_lof, k=actual_k)
        adj_norm = _normalize_adjacency(adj)

        # Step 6: Train (fine-tune) on this batch
        losses = self.train(features_with_lof, adj_norm)
        if losses:
            logger.debug("GCN-LOF training: %d epochs, final loss=%.4f", len(losses), losses[-1])

        # Step 7: Compute reconstruction error
        embeddings = self._encode(features_with_lof, adj_norm)
        reconstructed = self._reconstruct(embeddings)
        recon_error = self._compute_reconstruction_error(features_with_lof, reconstructed)
        norm_recon = _normalize_scores(recon_error)

        # Step 8: Combined anomaly score (A12: HISTORICAL anchoring, not
        # per-batch min-max — every batch has a 1.0 by construction under
        # min-max, so the worst event always clears a fixed threshold.
        # Anchor each component as a z-score against the persisted score
        # bank's running mean/std; benign batches then sit near zero.)
        lof_z = self._bank_zscore(lof_scores, "lof")
        recon_z = self._bank_zscore(recon_error, "recon")
        combined = self.alpha * lof_z + (1 - self.alpha) * recon_z

        # Step 9: Find KNN neighbors for top anomalies (for narrative context)
        # Build neighbor index for the top-scoring events
        anomaly_indices = np.where(combined > threshold)[0]

        # Build neighbor map for context
        neighbor_map = {}
        if len(anomaly_indices) > 0:
            adj_dense = adj.toarray()
            for idx in anomaly_indices:
                neighbors = np.where(adj_dense[idx] > 0)[0]
                neighbors = [j for j in neighbors if j != idx]  # Exclude self
                neighbor_map[int(idx)] = neighbors[:5]  # Top 5 neighbors

        # Step 10: Produce anomaly entries
        anomalies = []
        for idx in anomaly_indices:
            entry = entries[idx]
            score = float(combined[idx])
            lof_val = float(lof_scores[idx])
            recon_val = float(recon_error[idx])

            # Build neighbor context for narrative
            neighbor_entries = neighbor_map.get(int(idx), [])
            similar_events = []
            for n_idx in neighbor_entries:
                n_entry = entries[n_idx]
                similar_events.append({
                    "user": n_entry.get("user", ""),
                    "type": n_entry.get("type", ""),
                    "action": n_entry.get("action", ""),
                    "timestamp": n_entry.get("timestamp", ""),
                })

            anomaly = {
                "type": "gcn_lof_anomaly",
                "severity": "high" if score > 0.9 else "medium",
                "user": entry.get("user", entry.get("src_ip", entry.get("client_ip", "unknown"))),
                "source_ip": entry.get("source_ip", entry.get("src_ip", entry.get("client_ip", ""))),
                "timestamp": entry.get("timestamp", ""),
                "details": (
                    f"GCN-LOF anomaly (score={score:.3f}, lof={lof_val:.2f}, "
                    f"recon_err={recon_val:.4f})"
                ),
                "detection_method": "gcn_lof",
                "gcn_lof_score": round(score, 3),
                "lof_score": round(lof_val, 2),
                "reconstruction_error": round(recon_val, 4),
                "similar_events": similar_events,
            }

            # Add existing anomaly type if pre-flagged
            if entry.get("anomaly"):
                anomaly["details"] += f" [pre-flagged: {entry['anomaly']}]"

            anomalies.append(anomaly)

        logger.info(
            "GCN-LOF: %d/%d events flagged (threshold=%.2f, alpha=%.2f)",
            len(anomalies), len(entries), threshold, self.alpha,
        )
        return anomalies

    def to_dict(self) -> dict:
        """Serialize detector state for persistence."""
        return {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "embed_dim": self.embed_dim,
            "k_neighbors": self.k_neighbors,
            "lof_neighbors": self.lof_neighbors,
            "alpha": self.alpha,
            "dropout_rate": self.dropout_rate,
            "score_bank": self.score_bank,  # A12: historical anchoring persists
            "gcn1": self.gcn1.get_params(),
            "gcn2": self.gcn2.get_params(),
            "decoder": self.decoder.get_params(),
            "scaler_mean": self.scaler_mean.tolist() if self.scaler_mean is not None else None,
            "scaler_scale": self.scaler_scale.tolist() if self.scaler_scale is not None else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GCNLOFDetector":
        """Deserialize detector state from persistence."""
        detector = cls(
            input_dim=data.get("input_dim", 24),
            hidden_dim=data.get("hidden_dim", 32),
            embed_dim=data.get("embed_dim", 16),
            k_neighbors=data.get("k_neighbors", 10),
            lof_neighbors=data.get("lof_neighbors", 20),
            alpha=data.get("alpha", 0.5),
            dropout_rate=data.get("dropout_rate", 0.3),
        )
        detector.gcn1.set_params(data["gcn1"])
        detector.gcn2.set_params(data["gcn2"])
        detector.decoder.set_params(data["decoder"])
        if data.get("scaler_mean") is not None:
            detector.scaler_mean = np.array(data["scaler_mean"])
        if data.get("scaler_scale") is not None:
            detector.scaler_scale = np.array(data["scaler_scale"])
        if data.get("score_bank") is not None:
            detector.score_bank = data["score_bank"]  # A12 restore
        return detector

    def save(self, filepath: str) -> None:
        """Save detector state to a JSON file atomically.

        Args:
            filepath: Path to the model file.
        """
        from nabla.persistence import atomic_write_json
        atomic_write_json(filepath, self.to_dict())
        logger.info("Saved GCN-LOF model to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> "GCNLOFDetector":
        """Load detector state from a JSON file.

        Returns a fresh detector with random weights if the file doesn't exist.

        Args:
            filepath: Path to the model file.

        Returns:
            GCNLOFDetector instance.
        """
        if not os.path.exists(filepath):
            logger.info("No GCN-LOF model at %s, using random initialization", filepath)
            return cls()
        with open(filepath) as f:
            data = json.load(f)
        detector = cls.from_dict(data)
        logger.info("Loaded GCN-LOF model from %s", filepath)
        return detector
