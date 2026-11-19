from __future__ import annotations

import pytest

from scripts.evaluate_detection import (
    _validate_ground_truth,
    classification_metrics,
)


def test_classification_metrics_include_confusion_matrix_counts():
    actual = classification_metrics(
        [(True, True), (True, False), (False, True), (False, False)]
    )
    assert actual == {
        "true_positives": 1,
        "false_positives": 1,
        "true_negatives": 1,
        "false_negatives": 1,
        "precision": 0.5,
        "recall": 0.5,
        "f1": 0.5,
        "accuracy": 0.5,
        "total": 4,
    }


def test_classification_metrics_handle_zero_predictions_and_empty_data():
    actual = classification_metrics([(True, False), (False, False)])
    assert actual["precision"] == actual["recall"] == actual["f1"] == 0.0
    with pytest.raises(ValueError, match="At least one"):
        classification_metrics([])


def test_ground_truth_comes_from_declared_scenario_type_and_expected_level():
    assert _validate_ground_truth(
        {"id": "A1-synthetic", "type": "attack", "expected": {"min_risk_level": "HIGH"}}
    )
    assert not _validate_ground_truth(
        {"id": "B1-synthetic", "type": "benign", "expected": {"min_risk_level": "LOW"}}
    )
    with pytest.raises(ValueError, match="conflicts"):
        _validate_ground_truth(
            {"id": "A2-invalid", "type": "attack", "expected": {"min_risk_level": "LOW"}}
        )
