"""
AgentSentry â€” Phase 4 ML detection engine.

Trains an Isolation Forest per agent on that agent's own benign session
history, then scores new sessions against it. This is intentionally the
well-understood, explainable algorithm (see the research doc and our own
earlier discussion): the defensible part of this project isn't the
algorithm, it's (a) the agent-specific tool-call feature set feeding it and
(b) the explainability layer below, which most static MCP scanners don't
offer at all.

EXPLAINABILITY â€” HONEST LIMITATION:
Isolation Forest doesn't provide per-feature contribution scores natively
(unlike, say, SHAP values on a tree ensemble built for that purpose). What
this module does instead is compute a z-score for each feature against the
training baseline's mean/std, and rank features by |z|. This is a
heuristic, not a formally derived attribution â€” it's documented as such
here and in SECURITY.md rather than oversold as "the AI explains itself."
It is still far more actionable than a bare anomaly score, which is the
actual bar we're clearing (see the false-positive criticism of static
scanners in the research doc).

The Isolation Forest score is supplemented with a baseline-deviation score:
an observation can be far outside an individual feature's training range
while its forest score remains inside the training-score band. Deviations up
to three standard deviations are ignored, and larger deviations increase
risk linearly to a cap at eight standard deviations.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_DIR = Path(__file__).parent.parent / "models"

# Fixed feature order â€” every feature dict (from SessionFeatures.to_vector())
# must be projected into this exact order before touching numpy/sklearn.
FEATURE_ORDER = [
    "call_count",
    "unique_tools_used",
    "error_rate",
    "session_duration_sec",
    "avg_inter_call_gap_sec",
    "max_inter_call_gap_sec",
    "max_privilege_level",
    "start_privilege_level",
    "end_privilege_level",
    "privilege_escalation_distance",
    "avg_argument_entropy",
    "max_argument_entropy",
]

MIN_TRAINING_SESSIONS = 10  # below this, a baseline is not statistically meaningful
MODEL_FORMAT_VERSION = 1
DETECTOR_VERSION = "1.0.0"
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MODEL_MAX_BYTES = 100 * 1024 * 1024


class ModelCompatibilityError(ValueError):
    """A persisted baseline is not compatible with this detector version."""


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(callable(is_junction) and is_junction())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _trusted_directory(path: Path, *, create: bool = False) -> Path:
    candidate = Path(path).expanduser().absolute()
    if create:
        candidate.mkdir(parents=True, exist_ok=True)
    if candidate.exists() and not candidate.is_dir():
        raise ModelCompatibilityError("Configured model path is not a directory.")
    for ancestor in (candidate, *candidate.parents):
        if _is_link_or_junction(ancestor):
            raise ModelCompatibilityError(
                "Configured model directory cannot contain symbolic links or junctions."
            )
    try:
        return candidate.resolve(strict=candidate.exists())
    except OSError as exc:
        raise ModelCompatibilityError("Configured model directory cannot be resolved.") from exc


def _trusted_artifact(directory: Path, name: str) -> Path:
    path = directory / name
    if _is_link_or_junction(path):
        raise ModelCompatibilityError("Model artifacts cannot be symbolic links or junctions.")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ModelCompatibilityError("Model artifact is missing or cannot be resolved.") from exc
    if resolved.parent != directory or not resolved.is_file():
        raise ModelCompatibilityError("Model artifact escapes the configured trusted directory.")
    return resolved


class NotEnoughTrainingDataError(Exception):
    pass


@dataclass
class FeatureContribution:
    feature: str
    value: float
    baseline_mean: float
    z_score: float


class BehaviorAnomalyDetector:
    """Per-agent Isolation Forest baseline + scorer."""

    def __init__(self, agent_id: str, model_dir: Path = MODEL_DIR):
        if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
            raise ValueError("agent_id must be 1-128 safe filename characters (letters, digits, _, ., -).")
        self.agent_id = agent_id
        self.model_dir = _trusted_directory(Path(model_dir))
        self.model: IsolationForest | None = None
        self.means: np.ndarray | None = None
        self.stds: np.ndarray | None = None
        self.train_score_min: float | None = None
        self.train_score_max: float | None = None

    # ---- training -------------------------------------------------------

    def fit(self, feature_dicts: list[dict[str, float]]) -> None:
        if len(feature_dicts) < MIN_TRAINING_SESSIONS:
            raise NotEnoughTrainingDataError(
                f"Need at least {MIN_TRAINING_SESSIONS} benign sessions to build a baseline "
                f"for agent '{self.agent_id}', got {len(feature_dicts)}. "
                f"(No public dataset of real agent-hijack sessions exists yet, so baselines are "
                f"built from the agent's own observed benign traffic â€” documented in README.md.)"
            )
        X = self._to_matrix(feature_dicts)
        if X.ndim != 2 or X.shape[1] != len(FEATURE_ORDER) or not np.isfinite(X).all():
            raise ValueError("Training features must be a finite numeric matrix matching FEATURE_ORDER.")
        self.means = X.mean(axis=0)
        self.stds = X.std(axis=0)
        self.stds[self.stds == 0] = 1e-6  # avoid div-by-zero for constant features

        self.model = IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
        )
        self.model.fit(X)

        train_scores = self.model.score_samples(X)
        # Use 1st/99th percentile rather than raw min/max so a single training
        # outlier can't blow out the normalization range.
        self.train_score_min = float(np.percentile(train_scores, 1))
        self.train_score_max = float(np.percentile(train_scores, 99))

    # ---- scoring ----------------------------------------------------------

    def score(self, feature_dict: dict[str, float]) -> tuple[float, list[FeatureContribution]]:
        if self.model is None:
            raise RuntimeError(f"Detector for '{self.agent_id}' has not been fit or loaded yet.")

        x = self._to_matrix([feature_dict])
        raw_score = float(self.model.score_samples(x)[0])  # higher = more normal

        span = (self.train_score_max - self.train_score_min) or 1e-6
        # Training scores define the expected-normal band; being near its
        # lower edge is not itself anomalous. Risk grows only below that band.
        risk = 100.0 * max(0.0, self.train_score_min - raw_score) / span
        risk = float(np.clip(risk, 0.0, 100.0))

        contributions = self._feature_contributions(x[0])
        largest_deviation = max(abs(item.z_score) for item in contributions)
        deviation_risk = 100.0 * np.clip((largest_deviation - 3.0) / 5.0, 0.0, 1.0)
        risk = max(risk, float(deviation_risk))
        return risk, contributions

    def _feature_contributions(self, x_row: np.ndarray) -> list[FeatureContribution]:
        z_scores = (x_row - self.means) / self.stds
        # Clip: when a feature has ~zero variance in training (e.g. every benign
        # session used the exact same privilege level), the div-by-zero guard's
        # epsilon std can produce absurd magnitudes like "285716838761496 std devs".
        # The direction/ranking is still meaningful; the raw magnitude beyond a
        # point is not (documented limitation, same honesty policy as the module
        # docstring's note on z-scores being a heuristic, not a true attribution).
        z_scores = np.clip(z_scores, -50.0, 50.0)
        contributions = [
            FeatureContribution(
                feature=FEATURE_ORDER[i],
                value=float(x_row[i]),
                baseline_mean=float(self.means[i]),
                z_score=float(z_scores[i]),
            )
            for i in range(len(FEATURE_ORDER))
        ]
        contributions.sort(key=lambda c: abs(c.z_score), reverse=True)
        return contributions

    # ---- persistence / lifecycle ------------------------------------------

    @property
    def model_path(self) -> Path:
        return self.model_dir / f"{self.agent_id}.joblib"

    @property
    def metadata_path(self) -> Path:
        return self.model_dir / f"{self.agent_id}.metadata.json"

    def save(self) -> Path:
        """Atomically persist a versioned model and its integrity metadata.

        Joblib uses pickle internally: only load model files from a directory
        writable by the trusted AgentSentry service account.
        """
        self._validate_fitted_state()
        self.model_dir = _trusted_directory(self.model_dir, create=True)
        if _is_link_or_junction(self.model_path):
            raise ModelCompatibilityError(
                "Refusing to overwrite a linked model artifact."
            )
        if _is_link_or_junction(self.metadata_path):
            raise ModelCompatibilityError(
                "Refusing to overwrite linked model metadata."
            )
        payload = {
            "model": self.model,
            "means": self.means,
            "stds": self.stds,
            "train_score_min": self.train_score_min,
            "train_score_max": self.train_score_max,
            "feature_order": FEATURE_ORDER,
        }
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.agent_id}.", suffix=".tmp", dir=self.model_dir)
        os.close(fd)
        temp_model = Path(temp_name)
        temp_metadata = self.metadata_path.with_suffix(".metadata.json.tmp")
        try:
            joblib.dump(payload, temp_model)
            metadata = {
                "format_version": MODEL_FORMAT_VERSION,
                "detector_version": DETECTOR_VERSION,
                "agent_id": self.agent_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "training_sessions_minimum": MIN_TRAINING_SESSIONS,
                "feature_order": FEATURE_ORDER,
                "feature_count": len(FEATURE_ORDER),
                "training_score_min": self.train_score_min,
                "training_score_max": self.train_score_max,
                "sha256": _sha256(temp_model),
            }
            temp_metadata.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            os.replace(temp_model, self.model_path)
            os.replace(temp_metadata, self.metadata_path)
        finally:
            temp_model.unlink(missing_ok=True)
            temp_metadata.unlink(missing_ok=True)
        return self.model_path

    @classmethod
    def status(cls, agent_id: str, model_dir: Path = MODEL_DIR) -> dict:
        """Return lifecycle state without deserializing the model."""
        try:
            probe = cls(agent_id, model_dir)
            model_path = _trusted_artifact(probe.model_dir, probe.model_path.name)
            metadata_path = _trusted_artifact(probe.model_dir, probe.metadata_path.name)
        except ModelCompatibilityError as exc:
            if "missing or cannot be resolved" in str(exc):
                return {"status": "UNAVAILABLE", "reason": "Model or metadata file is missing."}
            return {"status": "INCOMPATIBLE", "reason": str(exc)}
        except ValueError as exc:
            return {"status": "INCOMPATIBLE", "reason": str(exc)}
        try:
            if model_path.stat().st_size > MODEL_MAX_BYTES:
                return {"status": "INCOMPATIBLE", "reason": "Model file exceeds the configured size limit."}
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                return {"status": "INCOMPATIBLE", "reason": "Model metadata must be a JSON object."}
            if (
                metadata.get("format_version") != MODEL_FORMAT_VERSION
                or metadata.get("detector_version") != DETECTOR_VERSION
                or metadata.get("feature_order") != FEATURE_ORDER
                or metadata.get("feature_count") != len(FEATURE_ORDER)
                or metadata.get("training_sessions_minimum") < MIN_TRAINING_SESSIONS
            ):
                return {"status": "INCOMPATIBLE", "reason": "Model format or feature schema differs."}
            if metadata.get("agent_id") != agent_id:
                return {"status": "INCOMPATIBLE", "reason": "Model metadata agent_id mismatch."}
            if not re.fullmatch(r"[a-f0-9]{64}", str(metadata.get("sha256", ""))):
                return {"status": "INCOMPATIBLE", "reason": "Model integrity metadata is invalid."}
            score_min = float(metadata["training_score_min"])
            score_max = float(metadata["training_score_max"])
            if not np.isfinite([score_min, score_max]).all() or score_max < score_min:
                return {"status": "INCOMPATIBLE", "reason": "Training score metadata is invalid."}
            if metadata.get("sha256") != _sha256(model_path):
                return {"status": "INCOMPATIBLE", "reason": "Model integrity check failed."}
            return {"status": "LOADED", "reason": "Versioned model and integrity metadata are present."}
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return {"status": "INCOMPATIBLE", "reason": "Model metadata is invalid or unreadable."}

    @classmethod
    def load(cls, agent_id: str, model_dir: Path = MODEL_DIR) -> "BehaviorAnomalyDetector":
        probe = cls(agent_id=agent_id, model_dir=model_dir)
        state = cls.status(agent_id, model_dir)
        if state["status"] != "LOADED":
            raise ModelCompatibilityError(f"Cannot load baseline for '{agent_id}': {state['reason']}")
        # IMPORTANT: joblib/pickle can execute code. The hash detects accidental
        # corruption, not a malicious writer who can replace both files.
        model_path = _trusted_artifact(probe.model_dir, probe.model_path.name)
        metadata_path = _trusted_artifact(probe.model_dir, probe.metadata_path.name)
        try:
            data = joblib.load(model_path)
        except (
            AttributeError,
            EOFError,
            ImportError,
            IndexError,
            KeyError,
            OSError,
            pickle.UnpicklingError,
            TypeError,
            ValueError,
        ) as exc:
            raise ModelCompatibilityError("Persisted model payload could not be deserialized.") from exc
        if not isinstance(data, dict) or data.get("feature_order") != FEATURE_ORDER:
            raise ModelCompatibilityError("Persisted model payload has an incompatible schema.")
        detector = probe
        detector.model = data.get("model")
        detector.means = np.asarray(data.get("means"), dtype=float)
        detector.stds = np.asarray(data.get("stds"), dtype=float)
        detector.train_score_min = float(data.get("train_score_min"))
        detector.train_score_max = float(data.get("train_score_max"))
        detector._validate_fitted_state()
        if not isinstance(detector.model, IsolationForest):
            raise ModelCompatibilityError("Persisted estimator is not an IsolationForest.")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if (
            detector.train_score_min != float(metadata["training_score_min"])
            or detector.train_score_max != float(metadata["training_score_max"])
        ):
            raise ModelCompatibilityError("Model payload and metadata disagree.")
        return detector

    def _validate_fitted_state(self) -> None:
        expected = (len(FEATURE_ORDER),)
        if self.model is None or self.means is None or self.stds is None:
            raise ValueError("Detector has no fitted model state.")
        if self.means.shape != expected or self.stds.shape != expected:
            raise ValueError("Persisted baseline arrays do not match the feature schema.")
        if not np.isfinite(self.means).all() or not np.isfinite(self.stds).all() or (self.stds <= 0).any():
            raise ValueError("Persisted baseline statistics are invalid.")
        if self.train_score_min is None or self.train_score_max is None:
            raise ValueError("Persisted training score bounds are missing.")
        if not np.isfinite([self.train_score_min, self.train_score_max]).all() or self.train_score_max < self.train_score_min:
            raise ValueError("Persisted training score bounds are invalid.")

    @staticmethod
    def _to_matrix(feature_dicts: list[dict[str, float]]) -> np.ndarray:
        return np.array(
            [[fd.get(key, 0.0) for key in FEATURE_ORDER] for fd in feature_dicts],
            dtype=float,
        )
