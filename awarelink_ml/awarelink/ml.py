"""Offline sparse linear inference. No training libraries or network calls at runtime."""

from __future__ import annotations

from collections import Counter
import ipaddress
import json
import math
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit
import zlib

FEATURE_VERSION = "crc32-logtf-l2-basehost-v3"
DIMENSIONS = 32768
MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 12000
_WORDS = re.compile(r"[a-z]+(?:'[a-z]+)?|\d+", re.ASCII)
_WEB = re.compile(r"(?:https?://|www\.)\S+", re.I)
_EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")
_SUSPICIOUS = re.compile(r"login|verify|secure|account|update|bank|wallet|password|signin", re.I)


def model_host(host: str) -> str:
    """A coarse base domain used identically in training, splitting and serving.

    No runtime PSL/network dependency. Private hosting providers deliberately
    collapse to one base domain: path/subdomain attacks need separate evidence.
    """
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    take = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {
        "ac", "co", "com", "edu", "gov", "net", "org", "mil", "sch"
    } else 2
    return ".".join(labels[-take:])


def _hash(feature: str) -> int:
    # CRC32 is stable across Python processes and platforms, unlike hash().
    return zlib.crc32(feature.encode("utf-8")) % (DIMENSIONS - 64) + 64


def _scaled_counts(names: list[str]) -> dict[int, float]:
    counts: Counter[int] = Counter(_hash(name) for name in names)
    values = {index: 1.0 + math.log(count) for index, count in counts.items()}
    norm = math.sqrt(sum(value * value for value in values.values())) or 1.0
    return {index: value / norm for index, value in values.items()}


def text_tokens(text: str) -> list[str]:
    text = _EMAIL.sub(" emailtoken ", _WEB.sub(" urltoken ", text[:MAX_TEXT_LENGTH].lower()))
    return ["numbertoken" if token.isdigit() else token for token in _WORDS.findall(text)]


def features(kind: str, text: str) -> dict[int, float]:
    """The SAME extractor is used in fitting, evaluation, export checks and serving."""
    if kind not in {"url", "scam", "news"}:
        raise ValueError("Unsupported analysis kind")
    if kind != "url":
        tokens = text_tokens(text)
        return _scaled_counts(["w:" + token for token in tokens] + [
            "b:" + left + " " + right for left, right in zip(tokens, tokens[1:])
        ])

    text = text[:MAX_URL_LENGTH]
    parsed = urlsplit(text if "://" in text else "https://" + text)
    host = model_host(parsed.hostname or "")
    grams: list[str] = []
    # PhiUSIIL's legitimate rows largely contain homepages while phishing rows
    # have deeper paths. Excluding path/query/scheme prevents that collection
    # artifact from treating ordinary documentation links as phishing. Base-
    # domain normalization also removes the corpus's strong www-prefix bias.
    for prefix, part in (("h:", host[:253]),):
        bounded = "^" + part + "$"
        for size in (3, 4):
            grams.extend(prefix + bounded[index:index + size] for index in range(len(bounded) - size + 1))
    values = _scaled_counts(grams)
    host_length = max(1, len(host))
    try:
        ipaddress.ip_address(host)
        host_is_ip = 1.0
    except ValueError:
        host_is_ip = 0.0
    entropy = -sum((count / host_length) * math.log2(count / host_length) for count in Counter(host).values())
    numeric = [
        0.0,
        math.log1p(len(host)) / 6,
        math.log1p(max((len(label) for label in host.split(".")), default=0)) / 6,
        0.0,
        sum(char in "aeiou" for char in host) / host_length,
        sum(char.isdigit() for char in host) / host_length,
        sum(not char.isalnum() for char in host) / host_length,
        0.0,
        min(host.count("-"), 10) / 10,
        0.0,
        0.0,
        0.0,
        host_is_ip,
        float("xn--" in host),
        0.0,
        0.0,
        entropy / 6,
        0.0,
        min(len(_SUSPICIOUS.findall(host)), 10) / 10,
    ]
    values.update({index: value for index, value in enumerate(numeric) if value})
    return values


def sigmoid(logit: float) -> float:
    if logit >= 0:
        return 1.0 / (1.0 + math.exp(-logit))
    exp_logit = math.exp(logit)
    return exp_logit / (1.0 + exp_logit)


class ModelRegistry:
    """Immutable models loaded once when the application starts.

    Missing, damaged or incompatible artifacts fail startup explicitly. There is
    no fallback that presents hand-written rules as a trained prediction.
    """

    def __init__(self, models_dir: Path):
        self._models: dict[str, dict[str, Any]] = {}
        for kind in ("url", "scam", "news"):
            path = Path(models_dir) / (kind + ".json")
            try:
                model = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise RuntimeError(f"Cannot load trained {kind} model from {path}") from exc
            if model.get("feature_version") != FEATURE_VERSION or model.get("kind") != kind:
                raise RuntimeError(f"Incompatible {kind} model artifact")
            weights = model.get("weights")
            if not isinstance(weights, list) or len(weights) != DIMENSIONS:
                raise RuntimeError(f"Invalid {kind} model dimensions")
            if not all(isinstance(value, (int, float)) and math.isfinite(value) for value in weights):
                raise RuntimeError(f"Invalid {kind} model weights")
            if not isinstance(model.get("intercept"), (int, float)) or not math.isfinite(model["intercept"]):
                raise RuntimeError(f"Invalid {kind} model intercept")
            self._models[kind] = model

    def predict(self, kind: str, text: str) -> dict[str, Any]:
        if kind not in self._models:
            raise ValueError("Unsupported analysis kind")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("Provide nonempty input")
        model = self._models[kind]
        limit = MAX_URL_LENGTH if kind == "url" else MAX_TEXT_LENGTH
        if len(text) > limit:
            raise ValueError(f"Input exceeds the {limit} character model limit")
        vector = features(kind, text)
        probability = sigmoid(model["intercept"] + sum(model["weights"][index] * value for index, value in vector.items()))
        if kind == "news":
            label = "review"
            signals = ["Research model compares wording with historical checked statements.",
                       "Source verification is required regardless of this score."]
        else:
            low, high = model["thresholds"]["low"], model["thresholds"]["high"]
            label = "high_risk" if probability >= high else "low_risk" if probability <= low else "review"
            if not vector:
                label = "review"
            if kind == "url":
                parsed = urlsplit(text if "://" in text else "https://" + text)
                host = (parsed.hostname or "").lower()
                signals = []
                if vector.get(12):
                    signals.append("The address uses an IP address as its host.")
                if len(text) > 140:
                    signals.append("The address is unusually long.")
                if host.count(".") >= 4:
                    signals.append("The host contains several subdomains.")
                if "@" in text:
                    signals.append("The address contains an @ character.")
                if "xn--" in host:
                    signals.append("The hostname uses internationalized encoding.")
                signals.append("Local model assessed base-domain spelling, structure and character patterns.")
            else:
                tokens = text_tokens(text)
                candidates = {"w:" + token for token in tokens if token != "numbertoken"}
                candidates.update("b:" + left + " " + right for left, right in zip(tokens, tokens[1:]))
                # Contributions are approximate because feature hashing can collide.
                ranked = sorted(((model["weights"][_hash(name)] * vector.get(_hash(name), 0), name[2:])
                                 for name in candidates), reverse=True)
                signals = [f"Spam-associated wording: {name!r}." for contribution, name in ranked[:3] if contribution > 0.18]
                signals.append("Local model assessed similarity to labeled SMS spam.")
                if not vector:
                    signals = ["No supported English word features were found; manual review is required."]
        return {
            "score": round(probability * 100),
            "label": label,
            "probability": round(probability, 6),
            "model": model["name"],
            "model_version": model["version"],
            "signals": signals,
            "limitations": list(model["limitations"]),
            "metrics": dict(model["evaluation"]["test"]),
        }

    def summary(self) -> dict[str, Any]:
        # A detached JSON-safe copy protects the loaded registry from callers.
        return json.loads(json.dumps({kind: {key: value for key, value in model.items() if key != "weights"}
                                     for kind, model in self._models.items()}))
