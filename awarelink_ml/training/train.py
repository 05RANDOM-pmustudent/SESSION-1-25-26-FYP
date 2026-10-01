"""Rebuild all three artifacts from attributed original datasets.

Requires training/requirements.txt; serving does not import those dependencies.
Raw datasets are downloaded only into --data-dir, outside the deliverable.
"""

from __future__ import annotations

import argparse
from array import array
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen
import zipfile

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, brier_score_loss, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awarelink.ml import DIMENSIONS, FEATURE_VERSION, ModelRegistry, features, model_host, sigmoid, text_tokens

SEED = 20261001
SOURCES = {
    "url": {
        "title": "PhiUSIIL Phishing URL (Website)",
        "landing_page": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "download": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        "archive": "phiusiil.zip", "directory": "phiusiil", "license": "CC BY 4.0",
        "citation": "Arvind Prasad and Shalini Chandra (2024). PhiUSIIL Phishing URL (Website). UCI Machine Learning Repository. doi:10.1016/j.cose.2023.103545.",
    },
    "scam": {
        "title": "SMS Spam Collection",
        "landing_page": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
        "download": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
        "archive": "sms.zip", "directory": "sms", "license": "CC BY 4.0",
        "citation": "Tiago Almeida and Jose Maria Gomez Hidalgo (2011). SMS Spam Collection. UCI Machine Learning Repository. doi:10.24432/C5CC84.",
    },
    "news": {
        "title": "LIAR v1.0",
        "landing_page": "https://aclanthology.org/P17-2067/",
        "download": "https://www.cs.ucsb.edu/~william/data/liar_dataset.zip",
        "archive": "liar.zip", "directory": "liar", "license": "Research purposes only; original sources retain copyright (bundled README)",
        "citation": 'William Yang Wang (2017). "Liar, Liar Pants on Fire": A New Benchmark Dataset for Fake News Detection. ACL. doi:10.18653/v1/P17-2067.',
    },
}


def download(url: str, path: Path) -> None:
    if path.exists():
        return
    print(f"Downloading {path.name}", flush=True)
    request = Request(url, headers={"User-Agent": "AwareLink-research-training/1.0"})
    with urlopen(request, timeout=90) as response, path.open("wb") as target:
        while chunk := response.read(1024 * 1024):
            target.write(chunk)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for source in SOURCES.values():
        archive = data_dir / source["archive"]
        download(source["download"], archive)
        destination = data_dir / source["directory"]
        destination.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as zipped:
            # Extract only flat dataset files, never trust archive member paths.
            for member in zipped.infolist():
                if member.is_dir() or Path(member.filename).name != member.filename or member.file_size > 100_000_000:
                    continue
                (destination / member.filename).write_bytes(zipped.read(member))
    download("https://publicsuffix.org/list/public_suffix_list.dat", data_dir / "public_suffix_list.dat")


class DomainGroups:
    """Training-only PSL grouping, including private suffixes and wildcard rules."""

    def __init__(self, path: Path):
        self.rules = set()
        self.exceptions = set()
        self.wildcards = set()
        for raw in path.read_text(encoding="utf-8").splitlines():
            rule = raw.strip()
            if not rule or rule.startswith("//"):
                continue
            if rule.startswith("!"):
                self.exceptions.add(rule[1:].encode("idna").decode("ascii"))
            elif rule.startswith("*."):
                self.wildcards.add(rule[2:].encode("idna").decode("ascii"))
            else:
                self.rules.add(rule.encode("idna").decode("ascii"))

    def group(self, host: str) -> str:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
        labels = host.split(".")
        suffix_length = 1
        for offset in range(len(labels)):
            suffix = ".".join(labels[offset:])
            if suffix in self.exceptions:
                suffix_length = len(labels) - offset - 1
                break
            if suffix in self.rules:
                suffix_length = max(suffix_length, len(labels) - offset)
            if offset + 1 < len(labels) and ".".join(labels[offset + 1:]) in self.wildcards:
                suffix_length = max(suffix_length, len(labels) - offset)
        return ".".join(labels[-(suffix_length + 1):])


def canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip() if "://" in value else "https://" + value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Invalid dataset URL")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    port = parsed.port
    if ":" in host:
        host = "[" + host + "]"
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    authority = host + (":" + str(port) if port and port != default_port else "")
    return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))


def url_dataset(data_dir: Path):
    path = next((data_dir / "phiusiil").glob("*.csv"))
    csv.field_size_limit(10_000_000)
    labels: dict[str, set[int]] = defaultdict(set)
    raw_count = invalid = 0
    with path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            raw_count += 1
            try:
                text = canonical_url(row["URL"])
                labels[text].add(1 - int(row["label"]))
            except (ValueError, UnicodeError):
                invalid += 1
    records = [(text, next(iter(values))) for text, values in labels.items() if len(values) == 1]
    grouper = DomainGroups(data_dir / "public_suffix_list.dat")
    base_groups = [model_host(urlsplit(text).hostname or "") for text, _ in records]
    registrable_groups = [grouper.group(urlsplit(text).hostname or "") for text, _ in records]
    # Connect BOTH identities before splitting. A lightweight runtime suffix
    # approximation and a full PSL can differ; grouping their connected
    # components prevents either identity from leaking across partitions.
    parents: dict[str, str] = {}

    def find(value: str) -> str:
        parents.setdefault(value, value)
        root = value
        while parents[root] != root:
            root = parents[root]
        while parents[value] != value:
            following = parents[value]
            parents[value] = root
            value = following
        return root

    for base, registrable in zip(base_groups, registrable_groups):
        left, right = find("m:" + base), find("r:" + registrable)
        if left != right:
            parents[right] = left
    groups = [find("m:" + value) for value in base_groups]
    indices = np.arange(len(records))
    train_valid, test = next(GroupShuffleSplit(n_splits=1, test_size=.20, random_state=SEED).split(indices, groups=groups))
    train_local, valid_local = next(GroupShuffleSplit(n_splits=1, test_size=.20, random_state=SEED + 1).split(train_valid, groups=np.asarray(groups)[train_valid]))
    splits = {"train": train_valid[train_local], "validation": train_valid[valid_local], "test": test}
    group_sets = {name: {groups[index] for index in split} for name, split in splits.items()}
    assert not group_sets["train"] & group_sets["validation"]
    assert not group_sets["train"] & group_sets["test"]
    assert not group_sets["validation"] & group_sets["test"]
    psl_sets = {name: {registrable_groups[index] for index in split} for name, split in splits.items()}
    assert not psl_sets["train"] & psl_sets["validation"]
    assert not psl_sets["train"] & psl_sets["test"]
    assert not psl_sets["validation"] & psl_sets["test"]
    metadata = {
        "raw_rows": raw_count, "usable_deduplicated_rows": len(records), "invalid_rows": invalid,
        "conflicting_normalized_urls_removed": sum(len(values) > 1 for values in labels.values()),
        "duplicate_or_conflict_rows_removed": raw_count - invalid - len(records),
        "label_mapping": {"0": "phishing -> positive 1", "1": "legitimate -> negative 0"},
        "fields_used": ["URL", "label"],
        "split_method": "GroupShuffleSplit of connected components linking coarse model base domains and full PSL registrable domains; seed 20261001; approx 64/16/20",
        "registrable_domain_overlap_between_splits": 0,
        "model_base_domain_overlap_between_splits": 0,
        "domain_group_counts": {name: len(values) for name, values in group_sets.items()},
        "public_suffix_list": {"source": "https://publicsuffix.org/list/public_suffix_list.dat", "sha256": sha256(data_dir / "public_suffix_list.dat")},
    }
    return records, splits, metadata


def text_signature(text: str) -> str:
    return " ".join(text_tokens(text))


def scam_dataset(data_dir: Path):
    by_signature: dict[str, list[tuple[str, int]]] = defaultdict(list)
    raw_count = 0
    path = data_dir / "sms" / "SMSSpamCollection"
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        label, text = line.split("\t", 1)
        raw_count += 1
        by_signature[text_signature(text)].append((text, int(label == "spam")))
    records = [values[0] for values in by_signature.values() if len({row[1] for row in values}) == 1]
    indices = np.arange(len(records))
    labels = np.array([row[1] for row in records])
    train_valid, test = train_test_split(indices, test_size=.15, random_state=SEED, stratify=labels)
    train, valid = train_test_split(train_valid, test_size=.15 / .85, random_state=SEED + 1, stratify=labels[train_valid])
    metadata = {
        "raw_rows": raw_count, "usable_deduplicated_rows": len(records),
        "duplicate_or_conflict_rows_removed": raw_count - len(records),
        "conflicting_text_groups_removed": sum(len({row[1] for row in values}) > 1 for values in by_signature.values()),
        "label_mapping": {"spam": "positive 1", "ham": "negative 0"},
        "fields_used": ["message", "label"],
        "split_method": "Stratified 70/15/15 after token-normalized deduplication; phone numbers, URLs and emails normalized; seed 20261001",
        "normalized_text_overlap_between_splits": 0,
    }
    return records, {"train": train, "validation": valid, "test": test}, metadata


def news_dataset(data_dir: Path):
    records, split_names = [], []
    raw_counts, signatures = Counter(), defaultdict(list)
    risk_labels = {"false", "pants-fire", "barely-true"}
    for name, filename in (("train", "train.tsv"), ("validation", "valid.tsv"), ("test", "test.tsv")):
        with (data_dir / "liar" / filename).open(encoding="utf-8", newline="") as source:
            for row in csv.reader(source, delimiter="\t"):
                if len(row) < 3:
                    continue
                raw_counts[name] += 1
                text, label = row[2], int(row[1] in risk_labels)
                signature = text_signature(text)
                signatures[signature].append(label)
                records.append((text, label))
                split_names.append(name)
    kept, seen, cleaned_names = [], set(), []
    for record, name in zip(records, split_names):
        signature = text_signature(record[0])
        if signature in seen or len(set(signatures[signature])) != 1:
            continue
        seen.add(signature)
        kept.append(record)
        cleaned_names.append(name)
    splits = {name: np.array([index for index, value in enumerate(cleaned_names) if value == name])
              for name in ("train", "validation", "test")}
    metadata = {
        "raw_rows": sum(raw_counts.values()), "raw_official_split_rows": dict(raw_counts),
        "usable_deduplicated_rows": len(kept), "duplicate_or_conflict_rows_removed": len(records) - len(kept),
        "conflicting_text_groups_removed": sum(len(set(values)) > 1 for values in signatures.values()),
        "label_mapping": {"false / pants-fire / barely-true": "positive 1", "half-true / mostly-true / true": "negative 0"},
        "fields_used": ["statement", "label"],
        "excluded_metadata": ["speaker", "party", "subject", "job title", "state", "speaker credit history", "context"],
        "split_method": "Original train/valid/test files; token-normalized duplicates removed globally, retain earliest split; conflicts excluded",
        "normalized_text_overlap_between_splits": 0,
    }
    return kept, splits, metadata


def sparse_matrix(kind: str, records):
    indices, data, pointer = array("i"), array("f"), array("i", [0])
    for text, _ in records:
        for index, value in sorted(features(kind, text).items()):
            indices.append(index)
            data.append(value)
        pointer.append(len(indices))
    return csr_matrix((np.frombuffer(data, dtype=np.float32), np.frombuffer(indices, dtype=np.int32),
                       np.frombuffer(pointer, dtype=np.int32)), shape=(len(records), DIMENSIONS))


def metrics(labels, probabilities, always_review=False, low_threshold=.2, high_threshold=.8):
    decisions = probabilities >= .5
    matrix = confusion_matrix(labels, decisions, labels=[0, 1]).tolist()
    high = probabilities >= high_threshold
    low = probabilities <= low_threshold
    return {
        "samples": len(labels), "positive_samples": int(sum(labels)), "negative_samples": int(len(labels) - sum(labels)),
        "accuracy_at_0_5": round(float(accuracy_score(labels, decisions)), 6),
        "precision_at_0_5": round(float(precision_score(labels, decisions, zero_division=0)), 6),
        "recall_at_0_5": round(float(recall_score(labels, decisions, zero_division=0)), 6),
        "f1_at_0_5": round(float(f1_score(labels, decisions, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
        "average_precision": round(float(average_precision_score(labels, probabilities)), 6),
        "brier_score": round(float(brier_score_loss(labels, probabilities)), 6),
        "confusion_matrix_at_0_5": matrix,
        "majority_class_accuracy": round(float(max(sum(labels), len(labels) - sum(labels)) / len(labels)), 6),
        "operating_thresholds": {"low": low_threshold, "high": high_threshold},
        "high_risk_count": 0 if always_review else int(sum(high)),
        "high_risk_precision": None if always_review or not sum(high) else round(float(np.mean(labels[high])), 6),
        "low_risk_count": 0 if always_review else int(sum(low)),
        "positive_rate_among_low_risk": None if always_review or not sum(low) else round(float(np.mean(labels[low])), 6),
        "review_fraction": 1.0 if always_review else round(float(np.mean(~(low | high))), 6),
    }


LIMITATIONS = {
    "url": [
        "Lexical hostname patterns cannot establish whether a website is safe or compromised.",
        "Subdomain, path, query, scheme, webpage, DNS, TLS and domain-age evidence are excluded from the trained base-domain model.",
        "Subdomain/path-specific phishing, private-hosting pages and compromised trusted websites cannot be detected from the base domain alone.",
        "Base-domain normalization uses last labels with common country-code handling, not a complete runtime Public Suffix List.",
        "Historical dataset artifacts and shared URL templates can inflate evaluation even with disjoint domains.",
        "A low score is not a guarantee; new campaigns and unusual legitimate sites can be misclassified.",
    ],
    "scam": [
        "Trained on historical English SMS spam, which is not the same as a modern scam dataset.",
        "Cannot reliably assess Malay or other unsupported languages, novel scams, or image-only content.",
        "Spam-like wording can appear in legitimate offers; a low score is not a guarantee.",
    ],
    "news": [
        "Research-only language baseline, not truth verification or a political-bias classifier.",
        "Every news result requires review: wording alone cannot prove or disprove a claim.",
        "Historical US political statements introduce topic and population bias and do not represent general news.",
        "Speaker and party metadata are excluded, but wording may still encode spurious political associations.",
        "LIAR permits research purposes only; review dataset rights before any commercial deployment.",
    ],
}


def fit(kind, records, splits, metadata, data_dir, model_dir):
    print(f"{kind}: feature extraction for {len(records)} deduplicated rows", flush=True)
    started = time.perf_counter()
    X = sparse_matrix(kind, records)
    y = np.array([label for _, label in records], dtype=np.int32)
    candidates = (1.0,) if kind == "url" else (.25, 1.0, 4.0)
    best, candidates_log = None, []
    for strength in candidates:
        model = LogisticRegression(C=strength, solver="liblinear", max_iter=1000, random_state=SEED)
        model.fit(X[splits["train"]], y[splits["train"]])
        probabilities = model.predict_proba(X[splits["validation"]])[:, 1]
        auc = roc_auc_score(y[splits["validation"]], probabilities)
        candidates_log.append({"C": strength, "validation_roc_auc": round(float(auc), 6), "iterations": int(model.n_iter_[0])})
        print(f"{kind}: C={strength} validation ROC-AUC={auc:.4f}", flush=True)
        if best is None or auc > best[0]:
            best = (auc, model)
    model = best[1]
    low, high = (.05, .95) if kind == "url" else (.2, .8)
    evaluation = {name: metrics(y[split], model.predict_proba(X[split])[:, 1], kind == "news", low, high)
                  for name, split in splits.items() if name != "train"}
    model_dir.mkdir(parents=True, exist_ok=True)
    source = dict(SOURCES[kind])
    source["archive_sha256"] = sha256(data_dir / source["archive"])
    source["retrieved_date"] = "2026-10-01"
    metadata.update(source)
    metadata["split_rows"] = {name: len(split) for name, split in splits.items()}
    metadata["split_positive_rows"] = {name: int(sum(y[split])) for name, split in splits.items()}
    # Verify signatures are disjoint regardless of splitting strategy.
    identity = (lambda value: value) if kind == "url" else text_signature
    identities = {name: {identity(records[index][0]) for index in split} for name, split in splits.items()}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        assert not identities[left] & identities[right], f"Leakage: {kind} {left}/{right}"
    artifact = {
        "kind": kind, "name": {"url": "URL base-domain logistic regression", "scam": "SMS spam logistic regression", "news": "LIAR language research baseline"}[kind],
        "version": "1.2.0" if kind == "url" else "1.0.0", "feature_version": FEATURE_VERSION, "dimensions": DIMENSIONS,
        "weights": [round(float(value), 10) for value in model.coef_[0]],
        "intercept": round(float(model.intercept_[0]), 10),
        "thresholds": {"low": low, "high": high},
        "deployment_status": "research_only_always_review" if kind == "news" else "research_baseline",
        "limitations": LIMITATIONS[kind], "dataset": metadata, "evaluation": evaluation,
        "training": {"seed": SEED, "algorithm": "L2 logistic regression, liblinear", "selected_C": model.C,
                     "selection": "Maximum validation ROC-AUC; held-out test accessed after model selection",
                     "candidates": candidates_log, "dependencies": {name: importlib.metadata.version(name) for name in ("numpy", "scipy", "scikit-learn")},
                     "operating_threshold_selection": "URL 0.05/0.95 conservative triage after external benign-domain sanity checks, without optimizing test labels; SMS 0.2/0.8 preset; news always review",
                     "elapsed_seconds": round(time.perf_counter() - started, 3)},
    }
    path = model_dir / (kind + ".json")
    path.write_text(json.dumps(artifact, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    parity_errors = []
    for index in splits["test"][:100]:
        vector = features(kind, records[index][0])
        probability = sigmoid(artifact["intercept"] + sum(artifact["weights"][key] * value for key, value in vector.items()))
        original = float(model.predict_proba(X[index])[:, 1][0])
        parity_errors.append(abs(probability - original))
    max_error = max(parity_errors)
    assert max_error < 1e-6, (kind, max_error)
    artifact["training"]["export_parity_max_probability_error"] = max_error
    path.write_text(json.dumps(artifact, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{kind}: TEST {json.dumps(evaluation['test'])}; parity max error={max_error:.2e}", flush=True)
    return {key: value for key, value in artifact.items() if key != "weights"}


def runtime_checks(model_dir):
    registry = ModelRegistry(model_dir)
    samples = {
        "url": ["https://www.python.org/", "https://docs.python.org/3/library/urllib.parse.html", "https://en.wikipedia.org/wiki/Machine_learning",
                "https://github.com/05RANDOM-pmustudent/SESSION-1-25-26-FYP", "http://192.0.2.1/account/login?verify=12345",
                "https://paypal-login-verification.example/secure/login", "https://secure-account-verify-38271.example/verify-your-password"],
        "scam": ["Can we meet at the library at six?", "Congratulations! You won a cash prize. Call now to claim your free reward!", "Your account is suspended. Send your password and OTP immediately."],
        "news": ["The city council approved a new bus route on Tuesday.", "A new study claims this treatment cures every disease overnight."],
    }
    predictions, latencies = {}, {}
    for kind, texts in samples.items():
        predictions[kind] = [{"input": text, "result": registry.predict(kind, text)} for text in texts]
        timings = []
        for _ in range(100):
            start = time.perf_counter()
            registry.predict(kind, texts[0])
            timings.append((time.perf_counter() - start) * 1000)
        latencies[kind] = {"p50_ms": round(float(np.percentile(timings, 50)), 3), "p95_ms": round(float(np.percentile(timings, 95)), 3),
                           "measurement": "100 warm predictions of the first illustrative sample on the training machine; excludes network and queue"}
    return {"illustrative_samples_not_evaluation": predictions, "runtime_inference_latency": latencies}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True, help="Raw datasets outside the deliverable")
    parser.add_argument("--model-dir", type=Path, default=ROOT / "models")
    parser.add_argument("--kind", choices=("all", "url", "scam", "news"), default="all")
    args = parser.parse_args()
    # Research-only LIAR data use is required for this FYP baseline.
    prepare(args.data_dir)
    outputs = {}
    for kind, loader in (("url", url_dataset), ("scam", scam_dataset), ("news", news_dataset)):
        if args.kind not in {"all", kind}:
            continue
        records, splits, metadata = loader(args.data_dir)
        outputs[kind] = fit(kind, records, splits, metadata, args.data_dir, args.model_dir)
    if args.kind == "all":
        report = {"generated_utc": datetime.now(timezone.utc).isoformat(), "models": outputs, **runtime_checks(args.model_dir)}
        (ROOT / "training" / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
