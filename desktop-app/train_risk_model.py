#!/usr/bin/env python3
"""SEDWTIAR File Sensitivity Risk Classifier — Training Pipeline.

This script:
1. Generates a synthetic labeled training dataset based on domain expertise
2. Trains a Random Forest classifier from scratch (no sklearn/numpy)
3. Evaluates accuracy on a held-out test set
4. Exports the trained model as a pure-Python module (risk_model.py)

Run with: python train_risk_model.py
"""

from __future__ import annotations

import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# 1. DOMAIN KNOWLEDGE — Extension-to-Risk-Tier Mapping
# ──────────────────────────────────────────────────────────────────────────────
# Based on NIST SP 800-60, ISO 27001, and ITAD best practices.

RISK_TIERS = {
    0: "NEGLIGIBLE",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}

# Ground-truth extension → risk tier assignments
EXTENSION_RISK_MAP: dict[str, int] = {
    # CRITICAL (4) — Cryptographic material, credentials, secrets
    ".key": 4, ".pem": 4, ".p12": 4, ".pfx": 4, ".ppk": 4,
    ".kdbx": 4, ".ovpn": 4, ".env": 4, ".asc": 4, ".gpg": 4,
    ".keystore": 4, ".jks": 4, ".crt": 4, ".cer": 4, ".der": 4,
    ".id_rsa": 4, ".id_ed25519": 4, ".ssh": 4, ".wallet": 4,

    # HIGH (3) — Structured data likely containing PII/financial data
    ".db": 3, ".sqlite": 3, ".sqlite3": 3, ".sql": 3, ".dump": 3,
    ".mdb": 3, ".accdb": 3, ".dbf": 3,
    ".csv": 3, ".tsv": 3, ".parquet": 3, ".avro": 3,
    ".xls": 3, ".xlsx": 3, ".xlsm": 3, ".xlsb": 3,
    ".pst": 3, ".ost": 3, ".eml": 3, ".mbox": 3, ".msg": 3,
    ".vcf": 3, ".vcard": 3,
    ".bak": 3, ".backup": 3,
    ".log": 3,  # Logs often contain IPs, usernames, session tokens

    # MEDIUM (2) — Documents that may contain business/personal info
    ".doc": 2, ".docx": 2, ".odt": 2, ".rtf": 2,
    ".pdf": 2, ".ppt": 2, ".pptx": 2, ".odp": 2,
    ".txt": 2, ".md": 2, ".tex": 2,
    ".json": 2, ".xml": 2, ".yaml": 2, ".yml": 2, ".toml": 2,
    ".ini": 2, ".cfg": 2, ".conf": 2,
    ".html": 2, ".htm": 2, ".mht": 2,
    ".one": 2, ".onenote": 2,

    # LOW (1) — Media, code files, generally lower inherent sensitivity
    ".jpg": 1, ".jpeg": 1, ".png": 1, ".gif": 1, ".bmp": 1,
    ".tif": 1, ".tiff": 1, ".heic": 1, ".webp": 1, ".raw": 1, ".dng": 1,
    ".svg": 1, ".ico": 1,
    ".mp3": 1, ".wav": 1, ".flac": 1, ".aac": 1, ".m4a": 1,
    ".ogg": 1, ".wma": 1, ".opus": 1,
    ".mp4": 1, ".mov": 1, ".avi": 1, ".mkv": 1, ".m4v": 1,
    ".wmv": 1, ".webm": 1, ".flv": 1,
    ".py": 1, ".js": 1, ".ts": 1, ".java": 1, ".c": 1, ".cpp": 1,
    ".cs": 1, ".go": 1, ".rs": 1, ".rb": 1, ".php": 1, ".swift": 1,
    ".css": 1, ".scss": 1, ".less": 1,
    ".sh": 1, ".ps1": 1, ".bat": 1, ".cmd": 1,

    # NEGLIGIBLE (0) — System/temp/binary files
    ".dll": 0, ".sys": 0, ".drv": 0, ".ocx": 0,
    ".tmp": 0, ".temp": 0, ".cache": 0, ".lock": 0,
    ".exe": 0, ".msi": 0, ".com": 0,
    ".iso": 0, ".img": 0, ".vhd": 0, ".vmdk": 0,
    ".ttf": 0, ".otf": 0, ".woff": 0, ".woff2": 0,
    ".dat": 0, ".bin": 0,
    ".lnk": 0, ".url": 0,
}

# Extension → risk group (used as feature #1)
EXTENSION_RISK_GROUPS: dict[str, int] = {
    "crypto_keys": 7, "databases": 6, "email_pim": 5,
    "spreadsheets": 4, "documents": 3, "code_config": 2,
    "media": 1, "system_binary": 0,
}

_EXT_TO_GROUP: dict[str, int] = {}
for ext, tier in EXTENSION_RISK_MAP.items():
    if tier == 4:
        _EXT_TO_GROUP[ext] = 7  # crypto_keys
    elif tier == 3:
        if ext in {".db", ".sqlite", ".sqlite3", ".sql", ".dump", ".mdb", ".accdb", ".dbf", ".parquet", ".avro"}:
            _EXT_TO_GROUP[ext] = 6  # databases
        elif ext in {".pst", ".ost", ".eml", ".mbox", ".msg", ".vcf", ".vcard"}:
            _EXT_TO_GROUP[ext] = 5  # email_pim
        elif ext in {".xls", ".xlsx", ".xlsm", ".xlsb", ".csv", ".tsv"}:
            _EXT_TO_GROUP[ext] = 4  # spreadsheets
        else:
            _EXT_TO_GROUP[ext] = 4  # spreadsheets/backup
    elif tier == 2:
        if ext in {".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
            _EXT_TO_GROUP[ext] = 2  # code_config
        else:
            _EXT_TO_GROUP[ext] = 3  # documents
    elif tier == 1:
        if ext in {".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go", ".rs", ".rb",
                   ".php", ".swift", ".css", ".scss", ".less", ".sh", ".ps1", ".bat", ".cmd"}:
            _EXT_TO_GROUP[ext] = 2  # code_config
        else:
            _EXT_TO_GROUP[ext] = 1  # media
    else:
        _EXT_TO_GROUP[ext] = 0  # system_binary


# ──────────────────────────────────────────────────────────────────────────────
# 2. FEATURE EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────

CRYPTO_EXTS = frozenset({".key", ".pem", ".p12", ".pfx", ".ppk", ".kdbx", ".gpg",
                         ".keystore", ".jks", ".crt", ".cer", ".der", ".wallet",
                         ".id_rsa", ".id_ed25519", ".ssh", ".asc", ".ovpn", ".env"})
DATABASE_EXTS = frozenset({".db", ".sqlite", ".sqlite3", ".sql", ".dump", ".mdb",
                           ".accdb", ".dbf", ".parquet", ".avro"})
DOCUMENT_EXTS = frozenset({".doc", ".docx", ".odt", ".rtf", ".pdf", ".ppt", ".pptx",
                           ".odp", ".txt", ".md", ".tex", ".one"})
CODE_EXTS = frozenset({".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go",
                       ".rs", ".rb", ".php", ".swift", ".env", ".sh", ".ps1",
                       ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"})
MEDIA_EXTS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
                        ".heic", ".webp", ".raw", ".dng", ".svg", ".ico",
                        ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma",
                        ".mp4", ".mov", ".avi", ".mkv", ".m4v", ".wmv", ".webm"})
EMAIL_EXTS = frozenset({".pst", ".ost", ".eml", ".mbox", ".msg", ".vcf", ".vcard"})
SPREADSHEET_EXTS = frozenset({".xls", ".xlsx", ".xlsm", ".xlsb", ".csv", ".tsv"})
ARCHIVE_EXTS = frozenset({".bak", ".backup", ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".iso", ".img", ".vhd", ".vmdk"})
SYSTEM_EXTS = frozenset({".dll", ".sys", ".drv", ".ocx", ".tmp", ".temp", ".cache", ".lock", ".exe", ".msi", ".com", ".ttf", ".otf", ".woff", ".woff2", ".dat", ".bin", ".lnk", ".url"})


def extract_features(extension: str, file_size: int = 0, is_hidden: bool = False) -> list[float]:
    """Extract 12 numerical features from file metadata."""
    ext = extension.lower()
    return [
        float(_EXT_TO_GROUP.get(ext, 0)),           # 0: ext_risk_group
        float(is_hidden),                             # 1: is_hidden
        math.log2(file_size + 1) if file_size > 0 else 0.0, # 2: file_size_log
        float(ext in CRYPTO_EXTS),                    # 3: is_encrypted_ext
        float(ext in DATABASE_EXTS),                  # 4: is_database_ext
        float(ext in DOCUMENT_EXTS),                  # 5: is_document_ext
        float(ext in CODE_EXTS),                      # 6: is_code_ext
        float(ext in MEDIA_EXTS),                     # 7: is_media_ext
        float(ext in SPREADSHEET_EXTS),               # 8: is_spreadsheet_ext
        float(ext in EMAIL_EXTS),                     # 9: is_email_ext
        float(ext in ARCHIVE_EXTS),                   # 10: is_archive_ext
        float(ext in SYSTEM_EXTS),                    # 11: is_system_ext
    ]


# ──────────────────────────────────────────────────────────────────────────────
# 3. SYNTHETIC TRAINING DATA GENERATION
# ──────────────────────────────────────────────────────────────────────────────

def _size_distribution(tier: int) -> int:
    """Sample a realistic file size (bytes) based on the tier."""
    if tier == 4:  # Keys/certs are tiny
        return random.randint(100, 50_000)
    elif tier == 3:  # Databases/spreadsheets vary widely
        return random.randint(1_000, 500_000_000)
    elif tier == 2:  # Documents
        return random.randint(500, 50_000_000)
    elif tier == 1:  # Media files tend to be large
        return random.randint(10_000, 2_000_000_000)
    else:  # System/temp files
        return random.randint(100, 10_000_000)


def _hidden_probability(tier: int) -> float:
    """Probability a file has the Windows hidden attribute."""
    return {4: 0.35, 3: 0.15, 2: 0.08, 1: 0.05, 0: 0.40}[tier]


def generate_training_data(n_samples: int = 5000, noise_rate: float = 0.10, seed: int = 42) -> tuple[list[list[float]], list[int]]:
    """Generate labeled synthetic dataset.

    Returns (features_matrix, labels).
    """
    rng = random.Random(seed)
    all_exts = list(EXTENSION_RISK_MAP.keys())
    # Group extensions by tier for balanced sampling
    tier_exts: dict[int, list[str]] = defaultdict(list)
    for ext, tier in EXTENSION_RISK_MAP.items():
        tier_exts[tier].append(ext)

    samples_per_tier = n_samples // 5
    features_matrix: list[list[float]] = []
    labels: list[int] = []

    for tier in range(5):
        exts = tier_exts[tier]
        for _ in range(samples_per_tier):
            ext = rng.choice(exts)
            size = _size_distribution(tier)
            hidden = rng.random() < _hidden_probability(tier)
            features = extract_features(ext, size, hidden)
            # Add controlled noise: 10% chance of shifting label by ±1
            label = tier
            if rng.random() < noise_rate:
                shift = rng.choice([-1, 1])
                label = max(0, min(4, tier + shift))
            features_matrix.append(features)
            labels.append(label)

    # Shuffle
    combined = list(zip(features_matrix, labels))
    rng.shuffle(combined)
    features_matrix = [c[0] for c in combined]
    labels = [c[1] for c in combined]

    return features_matrix, labels


# ──────────────────────────────────────────────────────────────────────────────
# 4. RANDOM FOREST IMPLEMENTATION (from scratch)
# ──────────────────────────────────────────────────────────────────────────────

def _gini_impurity(labels: list[int]) -> float:
    """Compute Gini impurity of a label list."""
    n = len(labels)
    if n == 0:
        return 0.0
    counts = Counter(labels)
    return 1.0 - sum((c / n) ** 2 for c in counts.values())


def _gini_gain(parent: list[int], left: list[int], right: list[int]) -> float:
    """Compute Gini gain from a split."""
    n = len(parent)
    if n == 0:
        return 0.0
    return (_gini_impurity(parent)
            - (len(left) / n) * _gini_impurity(left)
            - (len(right) / n) * _gini_impurity(right))


class DecisionTreeNode:
    """A single node in a decision tree."""

    def __init__(
        self,
        feature_index: int | None = None,
        threshold: float | None = None,
        left: "DecisionTreeNode | None" = None,
        right: "DecisionTreeNode | None" = None,
        prediction: int | None = None,
        confidence: float = 0.0,
        class_distribution: dict[int, int] | None = None,
    ):
        self.feature_index = feature_index
        self.threshold = threshold
        self.left = left
        self.right = right
        self.prediction = prediction
        self.confidence = confidence
        self.class_distribution = class_distribution or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        if self.prediction is not None:
            return {
                "leaf": True,
                "prediction": self.prediction,
                "confidence": round(self.confidence, 4),
                "distribution": self.class_distribution,
            }
        return {
            "leaf": False,
            "feature": self.feature_index,
            "threshold": round(self.threshold, 6),
            "left": self.left.to_dict() if self.left else None,
            "right": self.right.to_dict() if self.right else None,
        }


def _build_tree(
    X: list[list[float]],
    y: list[int],
    feature_indices: list[int],
    max_depth: int,
    min_samples_leaf: int,
    n_features_per_split: int,
    rng: random.Random,
    depth: int = 0,
) -> DecisionTreeNode:
    """Recursively build a decision tree."""
    counts = Counter(y)
    majority_class = counts.most_common(1)[0][0]
    majority_count = counts[majority_class]
    confidence = majority_count / len(y) if y else 0.0

    # Stopping conditions
    if (depth >= max_depth
            or len(set(y)) == 1
            or len(y) < 2 * min_samples_leaf):
        return DecisionTreeNode(
            prediction=majority_class,
            confidence=confidence,
            class_distribution=dict(counts),
        )

    # Random feature subset for this split
    n_to_sample = min(n_features_per_split, len(feature_indices))
    candidate_features = rng.sample(feature_indices, n_to_sample)

    best_gain = 0.0
    best_feature = None
    best_threshold = None
    best_left_idx: list[int] = []
    best_right_idx: list[int] = []

    for fi in candidate_features:
        values = sorted(set(row[fi] for row in X))
        if len(values) <= 1:
            continue
        # Try midpoints between consecutive unique values
        thresholds = [(values[i] + values[i + 1]) / 2 for i in range(len(values) - 1)]
        # Limit to 20 candidate thresholds for efficiency
        if len(thresholds) > 20:
            step = len(thresholds) // 20
            thresholds = thresholds[::step]

        for thresh in thresholds:
            left_idx = [i for i in range(len(X)) if X[i][fi] <= thresh]
            right_idx = [i for i in range(len(X)) if X[i][fi] > thresh]
            if len(left_idx) < min_samples_leaf or len(right_idx) < min_samples_leaf:
                continue
            left_y = [y[i] for i in left_idx]
            right_y = [y[i] for i in right_idx]
            gain = _gini_gain(y, left_y, right_y)
            if gain > best_gain:
                best_gain = gain
                best_feature = fi
                best_threshold = thresh
                best_left_idx = left_idx
                best_right_idx = right_idx

    if best_feature is None or best_gain < 1e-7:
        return DecisionTreeNode(
            prediction=majority_class,
            confidence=confidence,
            class_distribution=dict(counts),
        )

    left_X = [X[i] for i in best_left_idx]
    left_y = [y[i] for i in best_left_idx]
    right_X = [X[i] for i in best_right_idx]
    right_y = [y[i] for i in best_right_idx]

    return DecisionTreeNode(
        feature_index=best_feature,
        threshold=best_threshold,
        left=_build_tree(left_X, left_y, feature_indices, max_depth, min_samples_leaf,
                         n_features_per_split, rng, depth + 1),
        right=_build_tree(right_X, right_y, feature_indices, max_depth, min_samples_leaf,
                          n_features_per_split, rng, depth + 1),
    )


def _predict_tree(node: DecisionTreeNode, features: list[float]) -> tuple[int, float, dict[int, int]]:
    """Predict with a single tree. Returns (class, confidence, distribution)."""
    if node.prediction is not None:
        return node.prediction, node.confidence, node.class_distribution
    if features[node.feature_index] <= node.threshold:
        return _predict_tree(node.left, features)
    return _predict_tree(node.right, features)


class RandomForest:
    """Random Forest classifier — pure Python, no dependencies."""

    def __init__(
        self,
        n_trees: int = 25,
        max_depth: int = 8,
        min_samples_leaf: int = 3,
        max_features: str = "sqrt",
        bootstrap_fraction: float = 0.8,
        seed: int = 42,
    ):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.bootstrap_fraction = bootstrap_fraction
        self.seed = seed
        self.trees: list[DecisionTreeNode] = []
        self.n_features: int = 0

    def fit(self, X: list[list[float]], y: list[int]) -> None:
        """Train the random forest."""
        rng = random.Random(self.seed)
        n = len(X)
        self.n_features = len(X[0])
        feature_indices = list(range(self.n_features))

        if self.max_features == "sqrt":
            n_features_per_split = max(1, int(math.sqrt(self.n_features)))
        else:
            n_features_per_split = self.n_features

        bootstrap_size = int(n * self.bootstrap_fraction)
        self.trees = []

        for t in range(self.n_trees):
            # Bootstrap sample
            indices = [rng.randint(0, n - 1) for _ in range(bootstrap_size)]
            X_boot = [X[i] for i in indices]
            y_boot = [y[i] for i in indices]

            tree = _build_tree(
                X_boot, y_boot, feature_indices,
                self.max_depth, self.min_samples_leaf,
                n_features_per_split, rng,
            )
            self.trees.append(tree)
            print(f"  Tree {t + 1}/{self.n_trees} trained", end="\r")

        print(f"  {self.n_trees} trees trained successfully.        ")

    def predict(self, features: list[float]) -> tuple[int, float, dict[int, float]]:
        """Predict class with confidence. Returns (class, confidence, class_probabilities)."""
        votes: dict[int, int] = defaultdict(int)
        total_dist: dict[int, float] = defaultdict(float)

        for tree in self.trees:
            pred, conf, dist = _predict_tree(tree, features)
            votes[pred] += 1
            for cls, count in dist.items():
                total_dist[cls] += count

        # Majority vote
        predicted_class = max(votes, key=votes.get)
        confidence = votes[predicted_class] / len(self.trees)

        # Normalize distribution
        total = sum(total_dist.values())
        class_probs = {cls: round(count / total, 4) for cls, count in sorted(total_dist.items())}

        return predicted_class, confidence, class_probs

    def export_trees(self) -> list[dict]:
        """Export all trees as JSON-serializable dicts."""
        return [tree.to_dict() for tree in self.trees]


# ──────────────────────────────────────────────────────────────────────────────
# 5. EVALUATION METRICS
# ──────────────────────────────────────────────────────────────────────────────

def evaluate(model: RandomForest, X_test: list[list[float]], y_test: list[int]) -> dict:
    """Compute accuracy, per-class precision/recall/F1, and confusion matrix."""
    y_pred = []
    for x in X_test:
        pred, _, _ = model.predict(x)
        y_pred.append(pred)

    # Overall accuracy
    correct = sum(1 for p, t in zip(y_pred, y_test) if p == t)
    accuracy = correct / len(y_test)

    # Confusion matrix
    classes = sorted(set(y_test) | set(y_pred))
    confusion = {true: {pred: 0 for pred in classes} for true in classes}
    for t, p in zip(y_test, y_pred):
        confusion[t][p] += 1

    # Per-class metrics
    metrics = {}
    for cls in classes:
        tp = confusion[cls][cls]
        fp = sum(confusion[other][cls] for other in classes if other != cls)
        fn = sum(confusion[cls][other] for other in classes if other != cls)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        metrics[cls] = {
            "tier": RISK_TIERS[cls],
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(confusion[cls].values()),
        }

    # Weighted F1
    total_support = sum(m["support"] for m in metrics.values())
    weighted_f1 = sum(m["f1"] * m["support"] / total_support for m in metrics.values())

    return {
        "accuracy": round(accuracy, 4),
        "weighted_f1": round(weighted_f1, 4),
        "per_class": metrics,
        "confusion_matrix": confusion,
    }


# ──────────────────────────────────────────────────────────────────────────────
# 6. MODEL EXPORT — Generate risk_model.py
# ──────────────────────────────────────────────────────────────────────────────

def export_model_module(model: RandomForest, eval_results: dict, output_path: str) -> None:
    """Export the trained model as a self-contained Python module."""
    trees_json = json.dumps(model.export_trees(), indent=2)
    # Convert JSON booleans/null to Python booleans/None
    trees_python = trees_json.replace(": true", ": True").replace(": false", ": False").replace(": null", ": None")

    module_code = f'''"""SEDWTIAR File Sensitivity Risk Classifier — Trained Model.

Auto-generated by train_risk_model.py.
Model: Random Forest ({model.n_trees} trees, max_depth={model.max_depth})
Training accuracy: {eval_results["accuracy"]:.1%}
Weighted F1 score: {eval_results["weighted_f1"]:.4f}

CRITICAL recall: {eval_results["per_class"][4]["recall"]:.1%}
HIGH recall:     {eval_results["per_class"][3]["recall"]:.1%}

No external dependencies — pure Python stdlib only.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


# ─── Risk tier definitions ───────────────────────────────────────────────────

RISK_TIERS = {{
    0: "NEGLIGIBLE",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}}

RISK_COLORS = {{
    0: "#384358",   # Steel Slate (Negligible)
    1: "#22c55e",   # Green (Low)
    2: "#FFA586",   # Peach Coral (Medium)
    3: "#B51A2B",   # Crimson Red (High)
    4: "#B51A2B",   # Crimson Red (Critical)
}}

RISK_DESCRIPTIONS = {{
    0: "System/temp files — minimal data sensitivity concern",
    1: "Media/code files — lower inherent sensitivity",
    2: "Documents that may contain business-sensitive information",
    3: "Structured data likely containing PII or financial records",
    4: "Cryptographic keys, credentials, secrets — immediate breach risk",
}}


# ─── Extension mappings (from training) ──────────────────────────────────────

EXTENSION_RISK_MAP = {json.dumps(EXTENSION_RISK_MAP, indent=4)}

_EXT_TO_GROUP = {json.dumps(_EXT_TO_GROUP, indent=4)}

CRYPTO_EXTS = frozenset({json.dumps(sorted(CRYPTO_EXTS))})
DATABASE_EXTS = frozenset({json.dumps(sorted(DATABASE_EXTS))})
DOCUMENT_EXTS = frozenset({json.dumps(sorted(DOCUMENT_EXTS))})
CODE_EXTS = frozenset({json.dumps(sorted(CODE_EXTS))})
MEDIA_EXTS = frozenset({json.dumps(sorted(MEDIA_EXTS))})
EMAIL_EXTS = frozenset({json.dumps(sorted(EMAIL_EXTS))})
SPREADSHEET_EXTS = frozenset({json.dumps(sorted(SPREADSHEET_EXTS))})
ARCHIVE_EXTS = frozenset({json.dumps(sorted(ARCHIVE_EXTS))})
SYSTEM_EXTS = frozenset({json.dumps(sorted(SYSTEM_EXTS))})

MODEL_ACCURACY = {eval_results["accuracy"]}
MODEL_ACCURACY_PERCENT = "{eval_results['accuracy']:.1%}"


# ─── Feature extraction ─────────────────────────────────────────────────────

def extract_features(extension: str, file_size: int = 0, is_hidden: bool = False) -> list[float]:
    """Extract 12 numerical features from file metadata.

    Features:
      0: ext_risk_group     — Extension mapped to a risk group (0-7)
      1: is_hidden          — Whether the file has the hidden attribute
      2: file_size_log      — log2(file_size + 1)
      3: is_encrypted_ext   — Encryption/key file extension
      4: is_database_ext    — Database file extension
      5: is_document_ext    — Document file extension
      6: is_code_ext        — Code/config file extension
      7: is_media_ext       — Media file extension
      8: is_spreadsheet_ext — Spreadsheet file extension
      9: is_email_ext       — Email / PIM archive file extension
      10: is_archive_ext    — Archive / backup file extension
      11: is_system_ext     — OS binary / temporary file extension
    """
    ext = extension.lower()
    return [
        float(_EXT_TO_GROUP.get(ext, 0)),
        float(is_hidden),
        math.log2(file_size + 1) if file_size > 0 else 0.0,
        float(ext in CRYPTO_EXTS),
        float(ext in DATABASE_EXTS),
        float(ext in DOCUMENT_EXTS),
        float(ext in CODE_EXTS),
        float(ext in MEDIA_EXTS),
        float(ext in SPREADSHEET_EXTS),
        float(ext in EMAIL_EXTS),
        float(ext in ARCHIVE_EXTS),
        float(ext in SYSTEM_EXTS),
    ]


# ─── Trained model structure ────────────────────────────────────────────────

_TRAINED_TREES = {trees_python}


# ─── Prediction engine ──────────────────────────────────────────────────────

def _predict_node(node: dict, features: list[float]) -> tuple[int, float, dict]:
    """Walk a serialized decision tree node."""
    if node["leaf"]:
        return node["prediction"], node["confidence"], node["distribution"]
    if features[node["feature"]] <= node["threshold"]:
        return _predict_node(node["left"], features)
    return _predict_node(node["right"], features)


def predict_risk(extension: str, file_size: int = 0, is_hidden: bool = False) -> dict[str, Any]:
    """Predict the sensitivity risk tier for a single file.

    Args:
        extension: File extension including the dot (e.g., ".pdf")
        file_size: File size in bytes
        is_hidden: Whether the file has the Windows hidden attribute

    Returns:
        dict with keys: tier (int), label (str), color (str),
        confidence (float), description (str), probabilities (dict)
    """
    features = extract_features(extension, file_size, is_hidden)
    votes: dict[int, int] = defaultdict(int)
    total_dist: dict[int, float] = defaultdict(float)

    for tree in _TRAINED_TREES:
        pred, conf, dist = _predict_node(tree, features)
        votes[pred] += 1
        for cls_str, count in dist.items():
            cls = int(cls_str)
            total_dist[cls] += count

    predicted_class = max(votes, key=votes.get)
    confidence = votes[predicted_class] / len(_TRAINED_TREES)

    total = sum(total_dist.values())
    probabilities = {{cls: round(count / total, 4) for cls, count in sorted(total_dist.items())}}

    return {{
        "tier": predicted_class,
        "label": RISK_TIERS[predicted_class],
        "color": RISK_COLORS[predicted_class],
        "confidence": round(confidence, 4),
        "description": RISK_DESCRIPTIONS[predicted_class],
        "probabilities": probabilities,
    }}


def predict_category_risk(category_name: str, extensions: list[str] | None = None,
                          total_files: int = 0, total_bytes: int = 0) -> dict[str, Any]:
    """Predict risk for a file category (as returned by the scanner).

    Uses the dominant extension in the category name or the provided extensions list.
    """
    avg_size = total_bytes // max(total_files, 1)
    is_hidden = "hidden" in category_name.lower()

    # Try to extract extension from category name or use provided list
    if extensions:
        # Predict for each extension and take the highest risk
        predictions = [predict_risk(ext, avg_size, is_hidden) for ext in extensions]
        return max(predictions, key=lambda p: (p["tier"], p["confidence"]))

    # Map category names to representative extensions
    category_ext_map = {{
        "documents": ".docx", "office": ".docx", "pdf": ".pdf",
        "photos": ".jpg", "images": ".jpg",
        "video": ".mp4", "audio": ".mp3",
        "archives": ".zip", "backups": ".bak",
        "databases": ".db", "structured": ".db",
        "code": ".py", "scripts": ".py",
        "keys": ".key", "security": ".key",
    }}

    cat_lower = category_name.lower()
    ext = ".tmp"  # default
    for keyword, mapped_ext in category_ext_map.items():
        if keyword in cat_lower:
            ext = mapped_ext
            break

    return predict_risk(ext, avg_size, is_hidden)


def compute_device_risk_score(categories: list[dict]) -> dict[str, Any]:
    """Compute an aggregate device sensitivity score (0-100).

    Args:
        categories: List of dicts with keys: category, files, bytes

    Returns:
        dict with: score (0-100), level (str), color (str), breakdown (list)
    """
    if not categories:
        return {{"score": 0, "level": "CLEAN", "color": "#22c55e", "breakdown": []}}

    breakdown = []
    weighted_sum = 0.0
    total_files = 0

    for cat in categories:
        name = cat.get("category", "")
        n_files = cat.get("files", 0)
        n_bytes = cat.get("bytes", 0)
        prediction = predict_category_risk(name, total_files=n_files, total_bytes=n_bytes)
        weight = n_files * (prediction["tier"] + 1)
        weighted_sum += weight
        total_files += n_files
        breakdown.append({{
            "category": name,
            "files": n_files,
            "risk_tier": prediction["tier"],
            "risk_label": prediction["label"],
            "risk_color": prediction["color"],
            "confidence": prediction["confidence"],
        }})

    # Normalize to 0-100
    if total_files > 0:
        max_possible = total_files * 5  # tier 4 + 1 = 5
        raw_score = (weighted_sum / max_possible) * 100
        score = min(100, int(raw_score))
    else:
        score = 0

    if score >= 80:
        level, color = "CRITICAL", "#ef4444"
    elif score >= 60:
        level, color = "HIGH", "#f97316"
    elif score >= 40:
        level, color = "ELEVATED", "#eab308"
    elif score >= 20:
        level, color = "MODERATE", "#22c55e"
    else:
        level, color = "LOW", "#6b7280"

    return {{"score": score, "level": level, "color": color, "breakdown": breakdown}}
'''

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(module_code)


# ──────────────────────────────────────────────────────────────────────────────
# 7. MAIN — Training Pipeline
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("SEDWTIAR File Sensitivity Risk Classifier — Training Pipeline")
    print("=" * 70)

    # Step 1: Generate data
    print("\n[1/5] Generating synthetic training dataset (12,000 samples)...")
    X, y = generate_training_data(n_samples=12000, noise_rate=0.005, seed=42)
    print(f"  Generated {len(X)} samples with {len(X[0])} features each")
    print(f"  Class distribution: {dict(Counter(y))}")

    # Step 2: Train/test split (80/20)
    print("\n[2/5] Splitting into train (80%) and test (20%)...")
    split = int(len(X) * 0.8)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]
    print(f"  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    # Step 3: Train model
    print("\n[3/5] Training Random Forest (60 trees, max_depth=14)...")
    start = time.time()
    model = RandomForest(n_trees=60, max_depth=14, min_samples_leaf=2, seed=42)
    model.fit(X_train, y_train)
    elapsed = time.time() - start
    print(f"  Training completed in {elapsed:.2f} seconds")

    # Step 4: Evaluate
    print("\n[4/5] Evaluating on test set...")
    results = evaluate(model, X_test, y_test)
    print(f"\n  +==================================================+")
    print(f"  |  OVERALL ACCURACY:  {results['accuracy']:.1%}                       |")
    print(f"  |  WEIGHTED F1 SCORE: {results['weighted_f1']:.4f}                     |")
    print(f"  +==================================================+")
    print(f"\n  Per-class metrics:")
    print(f"  {'Tier':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"  {'-' * 52}")
    for cls in sorted(results["per_class"]):
        m = results["per_class"][cls]
        print(f"  {m['tier']:<12} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f} {m['support']:>10}")

    print(f"\n  Confusion Matrix:")
    classes = sorted(results["confusion_matrix"])
    header = "  Actual\\Pred " + " ".join(f"{RISK_TIERS[c]:>11}" for c in classes)
    print(header)
    for true_cls in classes:
        row = f"  {RISK_TIERS[true_cls]:<12} "
        row += " ".join(f"{results['confusion_matrix'][true_cls][pred_cls]:>11}" for pred_cls in classes)
        print(row)

    # Step 5: Export
    print("\n[5/5] Exporting trained model to risk_model.py...")
    output_path = str(Path(__file__).resolve().parent / "risk_model.py")
    export_model_module(model, results, output_path)
    print(f"  Saved to: {output_path}")
    file_size = os.path.getsize(output_path)
    print(f"  Module size: {file_size:,} bytes")

    # Also sync to backend risk_model.py
    backend_risk_model = Path(__file__).resolve().parent.parent / "backend" / "app" / "risk_model.py"
    if backend_risk_model.parent.exists():
        import shutil
        shutil.copy2(output_path, backend_risk_model)
        print(f"  Synced to backend: {backend_risk_model}")

    # Quick sanity check
    print("\n  Quick sanity checks:")
    for ext, expected in [(".key", "CRITICAL"), (".db", "HIGH"), (".pdf", "MEDIUM"), (".jpg", "LOW"), (".dll", "NEGLIGIBLE")]:
        features = extract_features(ext, 10000, False)
        pred, conf, _ = model.predict(features)
        actual = RISK_TIERS[pred]
        status = "PASS" if actual == expected else "FAIL"
        print(f"    {status} {ext:>8} -> {actual:<12} (expected {expected}, confidence {conf:.0%})")

    print("\n" + "=" * 70)
    print("Training pipeline complete. risk_model.py is ready for integration.")
    print("=" * 70)


if __name__ == "__main__":
    main()
