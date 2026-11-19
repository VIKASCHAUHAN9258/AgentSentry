"""Reproducibly evaluate the detector against labeled synthetic MCP scenarios."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lab.scenario_loader import load_scenarios
from scripts import run_scenario

POSITIVE_LEVELS = {"HIGH", "CRITICAL"}
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class Evaluation:
    scenario_id: str
    category: str
    truth: bool
    prediction: bool
    risk_level: str


def classification_metrics(
    labels: Iterable[tuple[bool, bool]],
) -> dict[str, int | float]:
    tp = fp = tn = fn = 0
    count = 0
    for truth, prediction in labels:
        count += 1
        if truth and prediction:
            tp += 1
        elif not truth and prediction:
            fp += 1
        elif not truth and not prediction:
            tn += 1
        else:
            fn += 1
    if not count:
        raise ValueError("At least one labeled evaluation is required.")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": (tp + tn) / count,
        "total": count,
    }


def _validate_ground_truth(scenario: dict) -> bool:
    scenario_type = scenario["type"]
    expected_level = scenario["expected"]["min_risk_level"]
    if scenario_type == "attack" and expected_level not in POSITIVE_LEVELS:
        raise ValueError(
            f"{scenario['id']}: attack label conflicts with expected risk level "
            f"{expected_level!r}; review the scenario ground truth."
        )
    if scenario_type == "benign" and expected_level in POSITIVE_LEVELS:
        raise ValueError(
            f"{scenario['id']}: benign label conflicts with expected risk level "
            f"{expected_level!r}; review the scenario ground truth."
        )
    return scenario_type == "attack"


def _temporary_project(source_root: Path, destination: Path) -> None:
    (destination / "mcp_lab").mkdir(parents=True)
    (destination / "lab_files" / "sandbox").mkdir(parents=True)
    shutil.copy2(
        source_root / "mcp_lab" / "vulnerable_server.py",
        destination / "mcp_lab" / "vulnerable_server.py",
    )
    (destination / "lab_files" / "notes.txt").write_text(
        "Synthetic benchmark notes. TODO: review local lab data.\n",
        encoding="utf-8",
    )
    (destination / "lab_files" / ".env").write_text(
        "API_KEY=FAKE-BENCHMARK-ONLY\n",
        encoding="utf-8",
    )


def evaluate_scenarios(scenarios: list[dict], source_root: Path = PROJECT_ROOT) -> list[Evaluation]:
    original_root = run_scenario.PROJECT_ROOT
    original_pythonpath = os.environ.get("PYTHONPATH")
    results: list[Evaluation] = []
    try:
        os.environ["PYTHONPATH"] = str(source_root)
        with tempfile.TemporaryDirectory(prefix="agentsentry-benchmark-") as directory:
            isolated_root = Path(directory)
            _temporary_project(source_root, isolated_root)
            run_scenario.PROJECT_ROOT = isolated_root
            for scenario in scenarios:
                truth = _validate_ground_truth(scenario)
                with tempfile.TemporaryDirectory(prefix="scenario-db-") as db_directory:
                    database = Path(db_directory) / "scenario.db"
                    _session_id, rows = asyncio.run(
                        run_scenario._execute(scenario, database)
                    )
                risk_level, _assessment = run_scenario._score(scenario, rows)
                results.append(
                    Evaluation(
                        scenario_id=scenario["id"],
                        category=scenario["id"].split("-", 1)[0],
                        truth=truth,
                        prediction=risk_level in POSITIVE_LEVELS,
                        risk_level=risk_level,
                    )
                )
    finally:
        run_scenario.PROJECT_ROOT = original_root
        if original_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = original_pythonpath
    return results


def _markdown_report(results: list[Evaluation]) -> str:
    metrics = classification_metrics((row.truth, row.prediction) for row in results)
    lines = [
        "# Synthetic detection benchmark",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "> This is a deterministic synthetic-lab replay, not an estimate of real-world",
        "> accuracy. Ground truth comes from each scenario's declared `type`; the",
        "> predicted-positive threshold is HIGH or CRITICAL risk. No persisted telemetry",
        "> or unreviewed session is used for training or evaluation.",
        "",
        f"Scenarios evaluated: **{len(results)}** "
        f"({sum(row.truth for row in results)} attacks, "
        f"{sum(not row.truth for row in results)} benign).",
        "",
        "## Confusion matrix",
        "",
        "| Ground truth | Predicted attack | Predicted benign |",
        "|---|---:|---:|",
        f"| Attack | {metrics['true_positives']} (TP) | {metrics['false_negatives']} (FN) |",
        f"| Benign | {metrics['false_positives']} (FP) | {metrics['true_negatives']} (TN) |",
        "",
        "## Aggregate metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Precision | {metrics['precision']:.3f} |",
        f"| Recall | {metrics['recall']:.3f} |",
        f"| F1 | {metrics['f1']:.3f} |",
        f"| Accuracy | {metrics['accuracy']:.3f} |",
        "",
        "## Results by scenario",
        "",
        "| Scenario | Category | Truth | Risk level | Prediction | Result |",
        "|---|---|---|---|---|---|",
    ]
    for row in results:
        correct = row.truth == row.prediction
        lines.append(
            f"| `{row.scenario_id}` | {row.category} | "
            f"{'Attack' if row.truth else 'Benign'} | {row.risk_level} | "
            f"{'Attack' if row.prediction else 'Benign'} | "
            f"{'Correct' if correct else 'Incorrect'} |"
        )

    categories = sorted({row.category for row in results})
    lines.extend(
        [
            "",
            "## Results by attack category",
            "",
            "| Category | Scenarios | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for category in categories:
        subset = [row for row in results if row.category == category]
        category_metrics = classification_metrics(
            (row.truth, row.prediction) for row in subset
        )
        lines.append(
            f"| {category} | {category_metrics['total']} | "
            f"{category_metrics['true_positives']} | "
            f"{category_metrics['false_positives']} | "
            f"{category_metrics['true_negatives']} | "
            f"{category_metrics['false_negatives']} | "
            f"{category_metrics['precision']:.3f} | "
            f"{category_metrics['recall']:.3f} | "
            f"{category_metrics['f1']:.3f} | "
            f"{category_metrics['accuracy']:.3f} |"
        )
    lines.extend(
        [
            "",
            "Category sample sizes are one scenario each in the current lab corpus;",
            "category-level rates are descriptive only. Expand the labeled scenario",
            "set before drawing conclusions about detection performance.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay labeled synthetic scenarios and write an evaluation report."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "docs" / "DETECTION_BENCHMARK.md",
    )
    args = parser.parse_args(argv)
    try:
        scenarios = load_scenarios()
        results = evaluate_scenarios(scenarios)
        report = _markdown_report(results)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        return 1
    print(report)
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
