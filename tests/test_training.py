"""Training set, split by batch, the model file, and score_process (PHASES.md steps 3.4, 3.5).

All data here is synthetic (tests/test_features.py builds the recordings).
"""

import ast
import csv
import json
from pathlib import Path

import pytest

from backend.pipeline import run_session
from tests.event_builder import POWERSHELL, P, Recording, stamp
from tests.test_features import attack_recording, labels_for, write_session
from triage import dataset, features, metrics, model, score, train
from triage.dataset import DatasetError

ROOT = Path(__file__).resolve().parent.parent


def benign_recording() -> Recording:
    recording = Recording()
    notepad = P(310, 100, "C:\\Windows\\notepad.exe", "notepad.exe")
    recording.start(notepad, 2.0)
    for i in range(8):  # a benign process that works for a while, so it has partial snapshots
        recording.add(notepad, "file_write", 3.0 + i * 0.5, path=f"C:\\Users\\lab\\AppData\\x{i}.tmp")
    recording.stop(notepad, 9.0)
    ghost = P(400, 1, "C:\\Windows\\System32\\svchost.exe", "svchost.exe")  # running before recording began
    recording.add(ghost, "file_write", 3.5, path="C:\\Windows\\Temp\\y.tmp")
    return recording


def write_labels(folder: Path, recording: Recording, malicious: bool, technique: str, **extra) -> None:
    rows = []
    for row in labels_for(recording):
        bad = malicious and row["label"] == "malicious"
        rows.append({**row, "label": "malicious" if bad else ("none" if row["label"] == "none" else "benign"),
                     "part": "test" if bad else "background", **extra})
        rows[-1]["technique"] = technique if bad else ""
    folder.mkdir(parents=True, exist_ok=True)
    with (folder / "labels.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def make_session(root: Path, name: str, recording: Recording, *, batch: int, pool="training-technique",
                 technique="T1486", malicious=True, part=True) -> None:
    sessions, labels = root / f"batch-{batch}", root / f"batch-{batch}-labels"
    write_session(sessions / name, recording, labels=False, session_id=name, batch=batch, pool=pool,
                  technique=technique if malicious else None, label="malicious" if malicious else "benign",
                  start_utc=stamp(0.8), end_utc=stamp(40))
    if part:
        write_labels(labels / name, recording, malicious, technique, pool=pool, session_id=name)
    else:
        (labels / name).mkdir(parents=True, exist_ok=True)
        rows = [{k: v for k, v in r.items()} for r in labels_for(recording)]
        with (labels / name / "labels.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


@pytest.fixture
def export(tmp_path):
    """Two batches. Batch 2 also has a held-out technique session."""
    for batch in (1, 2, 3):
        make_session(tmp_path, f"s{batch}-attack", attack_recording(), batch=batch)
        make_session(tmp_path, f"s{batch}-benign", benign_recording(), batch=batch, malicious=False)
    make_session(tmp_path, "s2-heldout", attack_recording(), batch=2, pool="held-out", technique="T1218.011")
    return tmp_path


def spec(export: Path):
    return [(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2, 3)]


# ---- metrics ------------------------------------------------------------------------------


def test_wilson_interval_is_wide_for_few_cases():
    assert metrics.wilson(0, 0) is None
    low, high = metrics.wilson(5, 5)
    assert low == pytest.approx(0.566, abs=0.001) and high == 1.0
    assert metrics.wilson(0, 117)[0] == 0.0


def test_confusion_counts_and_rates():
    result = metrics.confusion([0.9, 0.7, 0.6, 0.2, 0.1], [True, True, False, False, False], 0.65)
    assert (result["tp"], result["fn"], result["fp"], result["tn"]) == (2, 0, 0, 3)
    result = metrics.confusion([0.9, 0.2, 0.7, 0.1], [True, True, False, False], 0.5)
    assert (result["tp"], result["fn"], result["fp"], result["tn"]) == (1, 1, 1, 1)
    assert result["precision"]["value"] == 0.5 and result["recall"]["value"] == 0.5
    assert result["false_positive_rate"]["value"] == 0.5
    assert metrics.confusion([0.1], [False], 0.5)["precision"]["value"] is None  # nothing flagged


# ---- the dataset --------------------------------------------------------------------------


def test_positives_are_the_test_trees_and_the_rest_are_negatives(export):
    trees = dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")
    positives = [t for t in trees if t.positive]
    assert [t.row["root_pid"] for t in positives] == [200]
    assert all(not t.positive for t in trees if t.row["root_pid"] != 200)
    # Attack-session background trees stay as negatives, and the benign session is all negative.
    assert any(not t.positive and t.row["session_id"] == "s1-attack" for t in trees)
    assert any(t.row["session_id"] == "s1-benign" for t in trees)


def test_events_before_start_utc_are_dropped(export):
    trees = dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")
    unobserved = [t for t in trees if t.row["root_pid"] == 100 and t.row["session_id"] == "s1-attack"]
    assert unobserved == []  # its only event, at 0.5 s, is before start_utc (0.8 s)
    with_all = features.extract_session(export / "batch-1" / "s1-attack", export / "batch-1-labels")
    assert any(r["root_pid"] == 100 for r in with_all)  # not dropped without from_start


def test_unobserved_start_trees_never_train(export):
    batches = {n: dataset.load_batch(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2)}
    assert all(t.row["observed_start"] == 1 for t in dataset.training_trees(batches, [1, 2]))
    assert any(not t.usable for t in batches[1])  # the process that was already running (pid 400)
    table = dataset.balance_table(batches)
    assert {row["group"] for row in table} == {"training", "held-out"}


def test_held_out_sessions_never_reach_training_and_are_reported_apart(export):
    batches = {n: dataset.load_batch(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2)}
    training = dataset.training_trees(batches, [1, 2])
    assert "s2-heldout" not in {t.row["session_id"] for t in training}
    assert not any(t.held_out for t in training)
    ordinary, held_out = dataset.evaluation_trees(batches[2])
    assert {t.row["session_id"] for t in held_out} == {"s2-heldout"}
    assert "s2-heldout" not in {t.row["session_id"] for t in ordinary}


def test_pool_and_technique_must_agree_about_held_out(export):
    make_session(export, "s1-wrong", attack_recording(), batch=1, pool="training-technique", technique="T1053.005")
    with pytest.raises(DatasetError, match="disagree"):
        dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")
    make_session(export, "s1-wrong", attack_recording(), batch=1, pool="held-out", technique="T1486")
    with pytest.raises(DatasetError, match="disagree"):
        dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")


def test_labels_without_a_part_column_are_refused(export):
    make_session(export, "s1-old", attack_recording(), batch=1, part=False)
    with pytest.raises(DatasetError, match="harness"):
        dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")


def test_a_wrong_batch_number_and_missing_labels_are_refused(export):
    with pytest.raises(DatasetError, match="batch"):
        dataset.load_batch(7, export / "batch-1", export / "batch-1-labels")
    (export / "batch-1-labels" / "s1-attack" / "labels.csv").unlink()
    with pytest.raises(DatasetError, match="no labels"):
        dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")


# ---- the split and the report -------------------------------------------------------------


def test_every_fold_tests_on_a_batch_it_never_trained_on(export):
    report = train.run(spec(export), None)
    assert [(f["train_batches"], f["test_batch"]) for f in report["folds"]] == [([2, 3], 1), ([1, 3], 2), ([1, 2], 3)]
    for fold in report["folds"]:
        assert fold["test_batch"] not in fold["train_batches"]
    assert "PRELIMINARY" in report["status"]
    assert report["held_out_techniques"] == ["T1053.005", "T1685", "T1218.011"]
    held = report["folds"][1]["models"]["snapshots"]["held_out_techniques"]
    assert held["positives"] == 1
    assert report["folds"][0]["models"]["snapshots"]["held_out_techniques"]["trees"] == 0  # batch 1 has none


def test_the_report_has_precision_recall_and_false_positive_rate(export):
    report = train.run(spec(export), None)
    for fold in report["folds"]:
        assert set(fold["models"]) == {"complete", "snapshots"}
        for m in fold["models"].values():
            for threshold in m["test"]["by_threshold"]:
                assert {"precision", "recall", "false_positive_rate", "tp", "fp", "fn", "tn"} <= set(threshold)
            assert m["snapshots_of_test_trees"]["by_fraction"] and "alerts_scored" in m["alert_time_skew"]
    text = train.text_report(report)
    assert all(w in text for w in ("attacks caught", "benign flagged", "flagged that were attacks", "PRELIMINARY", "skew", "alert time", "95% CI"))


def test_the_saved_model_is_trained_without_held_out_sessions(export, tmp_path):
    out = tmp_path / "models"
    train.run(spec(export), out)
    meta = json.loads((out / model.META_FILE).read_text(encoding="utf-8"))
    assert "s2-heldout" not in meta["trained_sessions"]
    assert meta["held_out_techniques_excluded"] == ["T1053.005", "T1685", "T1218.011"]
    assert meta["trained_on_batches"] == [1, 2, 3] and "PRELIMINARY" in meta["status"]
    assert meta["training"] == "prefix snapshots"


def test_the_cli_refuses_an_output_inside_an_input(export, capsys):
    with pytest.raises(SystemExit):
        train.main(["--batch", "1", str(export / "batch-1"), str(export / "batch-1-labels"),
                    "--batch", "2", str(export / "batch-2"), str(export / "batch-2-labels"),
                    "--out", str(export / "batch-1" / "report"), "--no-save"])


# ---- the model ----------------------------------------------------------------------------


def test_model_features_are_behaviour_only():
    names = set(model.MODEL_FEATURES)
    assert names == set(features.FEATURE_COLUMNS) - {"n_fim_changes_linked"}
    assert not names & set(features.METADATA_COLUMNS)
    assert not {w for w in ("name", "path", "cmd", "cmdline", "image", "ext", "trusted", "rule", "user", "hash")
                if any(w in part.split("_") for part in names)}
    assert not names & {"network", "pool", "batch", "technique", "label", "session_id"}


def train_small(export: Path):
    batches = {n: dataset.load_batch(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2, 3)}
    rows = [t.row for t in dataset.training_trees(batches, [1, 2, 3])]
    return model.train(rows)


def test_save_and_load_round_trip_as_json(export, tmp_path):
    booster, info = train_small(export)
    assert info["scale_pos_weight"] == info["n_negative"] / info["n_positive"]
    model.save(booster, tmp_path / "m", {"status": "test"})
    text = (tmp_path / "m" / model.MODEL_FILE).read_text(encoding="utf-8")
    assert json.loads(text)  # JSON, not a pickle
    loaded = model.load(tmp_path / "m")
    assert loaded is not None and loaded.meta["status"] == "test"
    row = {name: 0 for name in model.MODEL_FEATURES}
    assert model.predict_vector(loaded.booster, row) == pytest.approx(model.predict_vector(booster, row))


def test_a_damaged_or_mismatched_model_is_not_used(export, tmp_path):
    booster, _ = train_small(export)
    folder = tmp_path / "m"
    assert model.load(folder) is None  # missing
    model.save(booster, folder, {})
    assert model.load(folder) is not None
    path = folder / model.MODEL_FILE
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    assert model.load(folder) is None  # SHA-256 differs
    model.save(booster, folder, {})
    meta_path = folder / model.META_FILE
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["features"] = meta["features"][:-1]
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    assert model.load(folder) is None  # feature list differs
    meta_path.write_text("not json", encoding="utf-8")
    assert model.load(folder) is None


def test_training_needs_both_classes():
    row = {name: 0 for name in model.MODEL_FEATURES}
    with pytest.raises(ValueError, match="cannot train"):
        model.train([{**row, "label": "benign"}] * 3)


# ---- score_process ------------------------------------------------------------------------


@pytest.fixture
def with_model(export, tmp_path, monkeypatch):
    booster, _ = train_small(export)
    model.save(booster, tmp_path / "scorer", {})
    monkeypatch.setattr(score, "MODEL_DIR", tmp_path / "scorer")
    score.reset_model()
    return booster


def tree_events(recording: Recording, root_pid: int) -> list[dict]:
    return [e for e in recording.events if e["pid"] in {root_pid, root_pid + 1, root_pid + 2}]


def test_no_model_means_not_scored_never_zero():
    assert score.is_stub() is True
    assert score.score_process(tree_events(attack_recording(), 200)) is None
    assert score.score_process([]) is None


def test_a_model_gives_a_score_between_0_and_1(with_model):
    assert score.is_stub() is False
    value = score.score_process(tree_events(attack_recording(), 200))
    assert isinstance(value, float) and 0.0 <= value <= 1.0


def test_trees_without_an_observed_start_or_with_bad_events_are_not_scored(with_model):
    recording = attack_recording()
    assert score.score_process([e for e in recording.events if e["pid"] == 100]) is None  # never started
    two_trees = [e for e in recording.events if e["pid"] in (200, 201, 202, 300)]
    assert score.score_process(two_trees) is None  # not a single tree
    assert score.score_process([{"event_id": "x"}]) is None
    assert score.score_process([]) is None


def test_scoring_and_training_use_the_same_features(export):
    """tree_feature_row is what score_process runs, so it must equal the training row, except
    for the one column a tree's own events cannot hold (linked FIM changes)."""
    session = export / "batch-1" / "s1-attack"
    for row, events in features.extract_session_trees(session, export / "batch-1-labels", from_start=True):
        if not row["observed_start"]:
            continue
        served = features.tree_feature_row(events)
        assert served is not None
        for name in model.MODEL_FEATURES:
            assert served[name] == row[name], name


def test_the_pipeline_scores_the_tree_the_model_was_trained_on(with_model, export):
    result = run_session(export / "batch-1" / "s1-attack", use_model=True)
    scored = [a["risk_score"] for a in result.alerts if a["subject"]["pid"] > 0]
    assert scored and all(isinstance(v, float) and 0 <= v <= 1 for v in scored)


def test_events_of_tree_containing_stops_at_an_unobserved_parent():
    recording = attack_recording()
    events = features.events_of_tree_containing(recording.events, 202)
    assert {e["pid"] for e in events} == {200, 201, 202}  # not pid 100, whose start was never seen
    assert features.events_of_tree_containing(recording.events, 99999) == []


# ---- repo hygiene ------------------------------------------------------------------------


def test_models_are_gitignored_and_never_pickled():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "triage/models/" in ignored and "*.pkl" in ignored
    source = (ROOT / "triage" / "model.py").read_text(encoding="utf-8")
    assert "pickle" not in source.replace("never pickle", "").replace("not pickle", "").replace("a pickle", "")


# ---- --use-model: the model score reaches no decision unless it is asked for -------------------


def decisions_of(result):
    return json.dumps([result.alerts, result.decisions, result.reports], sort_keys=True)


def test_without_use_model_the_score_is_never_used_even_with_a_model_present(with_model, export, tmp_path, monkeypatch):
    folder = export / "batch-1" / "s1-attack"
    default = run_session(folder)
    assert all(a["risk_score"] is None for a in default.alerts)
    assert default.model["used"] is False and default.model["loaded"] is True
    # Identical to a run on a machine with no model at all.
    monkeypatch.setattr(score, "MODEL_DIR", tmp_path / "empty")
    score.reset_model()
    assert decisions_of(run_session(folder)) == decisions_of(default)


def test_use_model_lets_the_score_in_and_states_the_model_sha256(with_model, export, tmp_path):
    folder = export / "batch-1" / "s1-attack"
    result = run_session(folder, use_model=True)
    assert any(isinstance(a["risk_score"], float) for a in result.alerts)
    meta = json.loads((score.MODEL_DIR / model.META_FILE).read_text(encoding="utf-8"))
    assert result.model["used"] is True and result.model["sha256"] == meta["model_sha256"]
    assert result.model["sha256"] == model.sha256_of(score.MODEL_DIR / model.MODEL_FILE)
    from backend.pipeline import output
    summary = output.write_session(result, folder, tmp_path / "out", None)
    assert summary["model"]["sha256"] == meta["model_sha256"] and summary["model"]["used"] is True
    assert "IN USE" in summary["notes"]["scorer"]
    off = output.summarise(run_session(folder), {}, "none")
    assert off["model"]["used"] is False and "NOT USED" in off["notes"]["scorer"]


def test_use_model_without_a_model_is_an_error_and_the_flag_is_off_by_default(export, tmp_path, capsys):
    from backend.pipeline import __main__ as cli
    args = ["--out", str(tmp_path / "out"), str(export / "batch-1")]
    with pytest.raises(SystemExit):
        cli.main(["--use-model", *args])
    assert "no valid model" in capsys.readouterr().err
    assert cli.main(args) == 0  # off by default: runs, with a null score everywhere
    summary = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    assert all(s["model"]["used"] is False for s in summary["sessions"])


def test_an_explicit_scorer_still_overrides(export):
    result = run_session(export / "batch-1" / "s1-attack", scorer=lambda events: 0.5)
    assert any(a["risk_score"] == 0.5 for a in result.alerts)
    assert result.model["used"] is False  # the model was not what scored it


# ---- prefix snapshots ---------------------------------------------------------------------


def trees_of(export, batch=1):
    return dataset.load_batch(batch, export / f"batch-{batch}", export / f"batch-{batch}-labels")


def attack_tree(export):
    return next(t for t in trees_of(export) if t.positive)


def test_snapshots_are_prefixes_of_the_tree_by_time(export):
    tree = attack_tree(export)
    snaps = dataset.snapshot_rows(tree)
    fractions = [f for f, _ in snaps]
    counts = [row["n_events"] for _, row in snaps]
    assert fractions == sorted(fractions) and fractions[-1] == 1.0
    assert counts == sorted(set(counts)) and counts[-1] == tree.row["n_events"]  # distinct, growing, whole tree last
    assert len(snaps) > 1
    for _, row in snaps:
        assert row["label"] == "malicious" and row["batch"] == 1  # a snapshot keeps its tree's label and metadata


def test_the_whole_tree_is_always_a_snapshot_and_equals_the_complete_row(export):
    for tree in trees_of(export):
        if not tree.usable:
            continue
        snaps = dataset.snapshot_rows(tree)
        assert snaps and snaps[-1][0] == 1.0
        full = snaps[-1][1]
        for name in model.MODEL_FEATURES:
            assert full[name] == tree.row[name], name


def test_partial_snapshots_need_enough_events_but_single_event_trees_are_kept(export):
    for tree in trees_of(export):
        if not tree.usable:
            continue
        snaps = dataset.snapshot_rows(tree)
        for fraction, row in snaps:
            assert fraction == 1.0 or row["n_events"] >= dataset.MIN_SNAPSHOT_EVENTS
        if tree.row["n_events"] == 1:
            assert [f for f, _ in snaps] == [1.0]


def test_benign_trees_get_snapshots_too(export):
    benign = [t for t in trees_of(export) if t.usable and not t.positive and t.row["n_events"] > 3]
    assert benign and any(len(dataset.snapshot_rows(t)) > 1 for t in benign)


def test_snapshots_come_from_the_trees_events_alone(export):
    """No label and no harness is read: change every label on the tree and the rows' features stay."""
    tree = attack_tree(export)
    before = dataset.snapshot_rows(tree)
    flipped = dataset.Tree({**tree.row, "label": "benign", "technique": ""}, tree.events)
    after = dataset.snapshot_rows(flipped)
    assert [{k: r[k] for k in model.MODEL_FEATURES} for _, r in before] == [{k: r[k] for k in model.MODEL_FEATURES} for _, r in after]


def test_snapshot_training_has_more_rows_than_complete_training_and_no_held_out(export):
    batches = {n: trees_of(export, n) for n in (1, 2)}
    trees = dataset.training_trees(batches, [1, 2])
    assert len(train.training_rows("snapshots", trees)) > len(train.training_rows("complete", trees)) == len(trees)
    assert "s2-heldout" not in {r["session_id"] for r in train.training_rows("snapshots", trees)}
    # Training rows only ever come from trees of the training batches given.
    only_one = dataset.training_trees(batches, [1])
    assert {r["batch"] for r in train.training_rows("snapshots", only_one)} == {1}


def test_the_saved_model_is_the_snapshot_model(export, tmp_path):
    report = train.run(spec(export), tmp_path / "m")
    assert report["final_model"]["training"] == "prefix snapshots"
    complete = report["folds"][0]["models"]["complete"]["train"]["n_positive"]
    assert report["folds"][0]["models"]["snapshots"]["train"]["n_positive"] >= complete
    assert len(report["final_model"]["sha256"]) == 64


# ---- the scorer is label-free -------------------------------------------------------------


def test_scoring_opens_no_file_at_all(with_model, monkeypatch):
    """No labels, session.json, model file or anything else may be read while scoring: the
    model is loaded before, and the scorer works on the events it is given."""
    events = tree_events(attack_recording(), 200)
    expected = score.score_process(events)  # also loads the model, once
    assert expected is not None
    import builtins
    import io
    import os

    def refuse(*args, **kwargs):
        raise AssertionError(f"scoring tried to open a file: {args[:1]}")

    monkeypatch.setattr(builtins, "open", refuse)
    monkeypatch.setattr(io, "open", refuse)
    monkeypatch.setattr(os, "open", refuse)
    monkeypatch.setattr(Path, "read_text", refuse)
    monkeypatch.setattr(Path, "read_bytes", refuse)
    monkeypatch.setattr(Path, "open", refuse)
    assert score.score_process(events) == expected


def test_labels_and_harness_markers_cannot_change_a_score(with_model):
    plain = tree_events(attack_recording(), 200)
    marked = [{**e, "label": "benign", "part": "harness", "technique": "", "malicious": False} for e in plain]
    assert score.score_process(marked) == score.score_process(plain)


def test_names_paths_and_command_lines_cannot_change_a_score(with_model):
    """The ML rule, at the scorer: rename everything a feature must ignore."""
    from tests.test_features import attack_recording as renamed_recording
    a = tree_events(attack_recording(), 200)
    b = tree_events(renamed_recording({"image": "C:\\Other\\zzz.exe", "cmd": "zzz --secret", "leaf": "other",
                                       "ext": ".enc", "ip": "198.51.100.7", "value": "Other"}), 200)
    assert score.score_process(a) is not None
    # The recordings differ in paths, names and command lines but not in what they do.
    assert score.score_process(a) == score.score_process(b)


def code_words(path: Path) -> set[str]:
    """Names, attributes, imports and string values in the code. Docstrings and comments are not code."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    words = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            words.add(node.id)
        elif isinstance(node, ast.Attribute):
            words.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            words.update(alias.name for alias in node.names)
            words.add(getattr(node, "module", None) or "")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            words.add(node.value)
    return words


def test_the_scorer_and_the_run_path_never_name_labels():
    """The scoring path has no label input. score.py reads no label file or session data at all.
    The pipeline reads session.json only to describe the session in the summary, and never labels."""
    scorer = code_words(ROOT / "triage/score.py")
    for word in ("labels.csv", "read_labels", "load_session", "session.json", "start_utc",
                 "harness_excluded", "labels_dir", "csv", "open", "read_text"):
        assert word not in scorer, f"triage/score.py uses {word}"
    pipeline = code_words(ROOT / "backend/pipeline/run.py")
    for word in ("labels.csv", "read_labels", "labels_dir", "harness_excluded", "start_utc", "part"):
        assert word not in pipeline, f"backend/pipeline/run.py uses {word}"
    import inspect
    assert list(inspect.signature(score.score_process).parameters) == ["events"]
    # What reaches the scorer is events: the pipeline's score() hands it nothing else.
    assert "events_of_tree_containing(proc.tree_events(), proc.pid)" in inspect.getsource(run_session.__globals__["Replay"].score)


def test_the_harness_is_not_removed_at_runtime_and_the_scorer_says_so(with_model):
    """A wrapper whose start was seen is part of the tree the scorer sees. Training left the
    harness out, using labels, and at runtime there are none. This is the known difference."""
    recording = attack_recording()
    seen = features.events_of_tree_containing(recording.events, 202)
    assert {e["pid"] for e in seen} == {200, 201, 202}  # the test's launcher (pid 200) is inside
    assert "SCOPE" in score.__doc__ and "label-free" in score.__doc__


# ---- a batch with a session that was decided out ---------------------------------------------


def test_sessions_without_labels_stop_the_run_unless_they_are_left_out_on_purpose(export):
    make_session(export, "s1-first-attempt", attack_recording(), batch=1)
    (export / "batch-1-labels" / "s1-first-attempt" / "labels.csv").unlink()
    with pytest.raises(DatasetError, match="no labels"):
        dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")  # strict by default
    trees = dataset.load_batch(1, export / "batch-1", export / "batch-1-labels", only_labelled=True)
    assert "s1-first-attempt" not in {t.row["session_id"] for t in trees}
    assert dataset.unlabelled_sessions(export / "batch-1", export / "batch-1-labels") == ["s1-first-attempt"]


def test_the_report_names_the_sessions_left_out(export):
    make_session(export, "s1-first-attempt", attack_recording(), batch=1)
    (export / "batch-1-labels" / "s1-first-attempt" / "labels.csv").unlink()
    report = train.run(spec(export), None, only_labelled=True)
    assert report["sessions_left_out_for_having_no_labels"] == {"1": ["s1-first-attempt"]}
    assert "s1-first-attempt" in train.text_report(report)
    with pytest.raises(DatasetError):
        train.run(spec(export), None)


def test_fewer_than_three_batches_cannot_choose_a_threshold_on_training_folds_only(export):
    with pytest.raises(DatasetError, match="at least three"):
        train.run(spec(export)[:2], None)


# ---- counts with intervals, thresholds from training folds only, T1003.001 apart --------------


def test_every_rate_is_shown_with_its_count_and_an_interval():
    assert metrics.show(9, 15) == "9 of 15 (60%, 95% CI 35.7% to 80.2%)"
    assert metrics.show(0, 44) == "0 of 44 (0%, 95% CI 0% to 8%)"
    assert metrics.show(0, 0) == "0 of 0 (no cases)"
    assert metrics.rate(5, 17)["k"] == 5 and metrics.rate(5, 17)["of"] == 17


def test_the_threshold_is_the_lowest_grid_value_within_the_false_positive_cap():
    benign = [0.1] * 97 + [0.55, 0.55, 0.55]  # 3 of 100 benign trees at 0.55: 3% at 0.5, 0% from 0.6
    scores = benign + [0.9, 0.95]
    flags = [False] * 100 + [True, True]
    chosen = train.choose_threshold(scores, flags)
    assert chosen["threshold"] == 0.6 and chosen["met_fpr_cap"] is True
    assert chosen["chosen_on"] == {"negatives": 100, "false_positives": 0, "positives": 2, "true_positives": 2}
    assert train.choose_threshold([0.1] * 100 + [0.9], [False] * 100 + [True])["threshold"] == 0.5
    stuck = train.choose_threshold([0.99] * 50 + [0.99], [False] * 50 + [True])
    assert stuck["threshold"] == 0.95 and stuck["met_fpr_cap"] is False  # nothing met it: the highest value
    assert train.choose_threshold([0.9], [True])["met_fpr_cap"] is False  # no benign trees to measure on


def test_a_threshold_never_depends_on_its_own_test_batch(export, tmp_path):
    """The threshold for the fold that tests batch N is chosen inside the other batches. Remove
    or change batch 1 entirely, and fold 1's choice does not move."""
    import shutil
    first = train.run(spec(export), None)
    chosen = lambda r, i: {m: r["folds"][i]["models"][m]["threshold_chosen_on_training_folds"] for m in train.MODES}  # noqa: E731
    changed = tmp_path / "changed"
    for n in (2, 3):
        shutil.copytree(export / f"batch-{n}", changed / f"batch-{n}")
        shutil.copytree(export / f"batch-{n}-labels", changed / f"batch-{n}-labels")
    make_session(changed, "x1-other", benign_recording(), batch=1, malicious=False)
    make_session(changed, "x1-attack", attack_recording(), batch=1)
    second = train.run(spec(changed), None)
    assert chosen(first, 0) == chosen(second, 0)  # test batch 1: untouched by what batch 1 holds
    for fold in first["folds"]:
        for m in fold["models"].values():
            assert m["threshold_chosen_on_training_folds"]["threshold"] in train.THRESHOLD_GRID


def test_inner_selection_only_sees_the_training_batches(export, monkeypatch):
    seen = []
    real = train.inner_scores
    monkeypatch.setattr(train, "inner_scores", lambda mode, batches, numbers, *rest: seen.append(list(numbers)) or real(mode, batches, numbers, *rest))
    report = train.run(spec(export), None)
    folds = [f["test_batch"] for f in report["folds"] for _ in train.MODES]
    assert len(seen) == len(folds)
    for numbers, test in zip(seen, folds):
        assert test not in numbers and len(numbers) == 2


def test_the_chosen_threshold_is_reported_next_to_the_fixed_ones(export):
    report = train.run(spec(export), None)
    for fold in report["folds"]:
        for m in fold["models"].values():
            ths = [(t["threshold"], t["chosen_on_training_folds"]) for t in m["test"]["by_threshold"]]
            chosen = m["threshold_chosen_on_training_folds"]["threshold"]
            assert {0.5, 0.8, chosen} == {t for t, _ in ths}
            assert [t for t, flag in ths if flag] == [chosen]
    proposed = report["final_model"]["proposed_threshold"]
    assert proposed["threshold"] in train.THRESHOLD_GRID and "not a test result" in proposed["note"]


@pytest.fixture
def with_lsass(export):
    make_session(export, "s1-lsass", attack_recording(), batch=1, technique="T1003.001")
    make_session(export, "s2-lsass", attack_recording(), batch=2, technique="T1003.001")
    return export


def test_t1003_attack_trees_are_set_apart_and_never_count_toward_recall(with_lsass):
    batches = {n: trees_of(with_lsass, n) for n in (1, 2, 3)}
    for n in (1, 2):
        limited = dataset.limited_trees(batches[n])
        ordinary, held_out = dataset.evaluation_trees(batches[n])
        assert len(limited) == 1 and limited[0].row["technique"] == "T1003.001" and limited[0].positive
        assert all(t.row["tree_id"] != limited[0].row["tree_id"] for t in ordinary + held_out)
        # Its benign neighbours in the same session stay negatives.
        assert any(t.row["session_id"] == f"s{n}-lsass" and not t.positive for t in ordinary)
    # Left out of training by default, and still there when asked for.
    assert not any(t.limited for t in dataset.training_trees(batches, [1, 2, 3]))
    assert any(t.limited for t in dataset.training_trees(batches, [1, 2, 3], include_limited=True))
    report = train.run(spec(with_lsass), None)
    for fold in report["folds"]:
        m = fold["models"]["snapshots"]
        assert m["test"]["positives"] == 1 + 0  # the ordinary T1486 attack only, not the T1003.001 tree
        lim = m["documented_limitation"]
        assert lim["trees"] == (1 if fold["test_batch"] in (1, 2) else 0)
    pooled = report["pooled"]["snapshots"]["documented_limitation"]
    assert pooled["trees"] == 2 and len(pooled["scores"]) == 2
    ordinary_attacks = sum(r["positive_trees"] for r in report["balance"] if r["group"] == "training")
    assert ordinary_attacks == 3  # one ordinary attack tree per batch
    assert all(r["documented_limitation_trees"] == (1 if r["batch"] in (1, 2) and r["group"] == "training" else 0)
               for r in report["balance"])


def test_the_text_report_lists_t1003_apart_and_sums_with_counts_and_intervals(with_lsass):
    report = train.run(spec(with_lsass), None)
    text = train.text_report(report)
    assert "T1003.001 (documented limitation, NOT in recall)" in text
    assert "Summed over the held-out batches" in text and "95% CI" in text
    for mode in train.MODES:
        pooled = report["pooled"][mode]
        folds = [f["models"][mode]["test"] for f in report["folds"]]
        at = lambda g, th: next(t for t in g["by_threshold"] if t["threshold"] == th)  # noqa: E731
        assert pooled["test"]["fixed_0.8"]["tp"] == sum(at(g, 0.8)["tp"] for g in folds)
        assert pooled["test"]["fixed_0.8"]["fp"] == sum(at(g, 0.8)["fp"] for g in folds)
        assert pooled["test"]["fixed_0.8"]["recall"]["of"] == pooled["test"]["fixed_0.8"]["tp"] + pooled["test"]["fixed_0.8"]["fn"]


def test_use_model_stays_off_by_default_and_policy_is_untouched():
    import inspect
    assert inspect.signature(run_session).parameters["use_model"].default is False
    from backend.pipeline import __main__ as cli
    assert "--use-model" in inspect.getsource(cli) and 'action="store_true"' in inspect.getsource(cli)
    for name in ("rules/policy.yaml", "policy/engine.py", "policy/loader.py"):
        assert "triage" not in (ROOT / name).read_text(encoding="utf-8").lower().replace("triage_", "")


def test_the_comparison_tables_show_counts_with_intervals_for_each_report(export):
    from triage import compare
    first = train.run(spec(export), None)
    second = train.run(spec(export), None)
    text = compare.markdown({"A": first, "B": second})
    assert "| A | B |" in text.replace("| complete model, summed over the held-out batches | A | B |", "| A | B |")
    assert text.count("95% CI") > 20 and "NOT in recall" in text and "Threshold chosen on training folds" in text
    assert "T1003.001 score (events)" in text


# ---- T1003.001 is left out of training by default ------------------------------------------


def test_limited_trees_are_left_out_of_training_by_default_and_can_be_put_back(with_lsass):
    batches = {n: trees_of(with_lsass, n) for n in (1, 2, 3)}
    default = dataset.training_trees(batches, [1, 2, 3])
    included = dataset.training_trees(batches, [1, 2, 3], include_limited=True)
    assert not any(t.limited for t in default) and any(t.limited for t in included)
    assert len(included) - len(default) == sum(t.limited for t in included) == 2
    # Their benign neighbours (same sessions) stay, and held-out sessions never train either way.
    assert any(t.row["session_id"] == "s1-lsass" and not t.positive for t in default)
    assert not any(t.held_out for t in default + included)
    assert {r["session_id"] for r in train.training_rows("snapshots", default)} == {t.row["session_id"] for t in default}


def test_the_default_reaches_every_training_step_and_t1003_is_still_reported_apart(with_lsass, monkeypatch):
    seen = []
    real = dataset.training_trees
    monkeypatch.setattr(train, "training_trees", lambda b, n, include_limited=False: seen.append(include_limited) or real(b, n, include_limited))
    report = train.run(spec(with_lsass), None)
    assert seen and not any(seen)  # outer folds, the threshold's inner folds and the final model
    assert report["documented_limitation"]["in_training"] is False and "LEFT OUT" in report["documented_limitation"]["note"]
    assert "no behaviour to learn" in report["documented_limitation"]["note"]
    assert report["final_model"]["t1003_in_training"] is False
    for fold in report["folds"]:
        assert fold["models"]["snapshots"]["documented_limitation"]["trees"] == (1 if fold["test_batch"] in (1, 2) else 0)
    assert report["pooled"]["snapshots"]["documented_limitation"]["trees"] == 2
    seen.clear()
    included = train.run(spec(with_lsass), None, include_limited_in_training=True)
    assert seen and all(seen)
    assert included["documented_limitation"]["in_training"] is True and included["final_model"]["t1003_in_training"] is True
    assert included["final_model"]["n_positive"] > report["final_model"]["n_positive"]


def test_the_cli_default_leaves_them_out_and_the_old_flag_is_gone(with_lsass, tmp_path):
    import inspect
    source = inspect.getsource(train.main)
    assert "--include-limited-in-training" in source and "--exclude-limited-from-training" not in source
    assert inspect.signature(train.run).parameters["include_limited_in_training"].default is False
    assert inspect.signature(dataset.training_trees).parameters["include_limited"].default is False
    plan = tmp_path / "recording_tests.json"
    plan.write_text(json.dumps({"tests": [], "excluded_from_ml_pools": ["fim-test-only"]}), encoding="utf-8")
    code = train.main(["--batch", "1", str(with_lsass / "batch-1"), str(with_lsass / "batch-1-labels"),
                       "--batch", "2", str(with_lsass / "batch-2"), str(with_lsass / "batch-2-labels"),
                       "--batch", "3", str(with_lsass / "batch-3"), str(with_lsass / "batch-3-labels"),
                       "--recording-tests", str(plan), "--out", str(tmp_path / "out")])
    assert code == 0
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["documented_limitation"]["in_training"] is False


# ---- the exclusion is by technique, not by size ----------------------------------------------


def powershell_startup_recording(events_in_tree: int) -> Recording:
    """One process that only starts, writes some temp files and stops: what a PowerShell
    start-up looks like when LSA protection stopped the dump. No LSASS access at all."""
    recording = Recording()
    shell = P(200, 100, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe")
    recording.start(shell, 1.0)
    for i in range(events_in_tree - 2):
        recording.add(shell, "file_write", 1.1 + i * 0.01, path=f"C:\\Windows\\Temp\\ps-startup-{i}.tmp")
    recording.stop(shell, 2.0)
    return recording


def test_a_t1003_tree_is_excluded_whatever_its_size_a_56_event_one_included(export):
    make_session(export, "s1-lsass56", powershell_startup_recording(56), batch=1, technique="T1003.001")
    batches = {n: trees_of(export, n) for n in (1, 2, 3)}
    tree = next(t for t in batches[1] if t.row["session_id"] == "s1-lsass56" and t.positive)
    assert tree.row["n_events"] == 56 and tree.row["technique"] == "T1003.001"
    assert tree.row["sysmon_lsass_access"] == 0 and tree.row["sysmon_lsass_vm_read"] == 0  # normal start-up only
    assert tree.limited  # by technique: 56 events does not make it a normal attack tree
    assert tree in dataset.limited_trees(batches[1])
    ordinary, held_out = dataset.evaluation_trees(batches[1])
    assert tree not in ordinary + held_out  # never in recall
    default = dataset.training_trees(batches, [1, 2, 3])
    assert tree not in default
    assert tree in dataset.training_trees(batches, [1, 2, 3], include_limited=True)
    assert tree.row["tree_id"] not in {r["tree_id"] for r in train.training_rows("snapshots", default)}
    # Reported apart, with its real size, in the fold that tests batch 1.
    report = train.run(spec(export), None)
    fold = next(f for f in report["folds"] if f["test_batch"] == 1)
    items = fold["models"]["snapshots"]["documented_limitation"]["items"]
    assert [i["n_events"] for i in items] == [56]
    assert report["final_model"]["t1003_in_training"] is False


def test_a_tiny_attack_tree_of_another_technique_is_not_limited_and_stays_in_training(export):
    """The rule is not 'few events': a 2-event tree of a technique that is not listed trains."""
    make_session(export, "s1-tiny", powershell_startup_recording(2), batch=1, technique="T1486")
    batches = {n: trees_of(export, n) for n in (1, 2, 3)}
    tree = next(t for t in batches[1] if t.row["session_id"] == "s1-tiny" and t.positive)
    assert tree.row["n_events"] == 2 and tree.row["technique"] == "T1486"
    assert not tree.limited
    assert tree in dataset.training_trees(batches, [1, 2, 3])
    ordinary, _ = dataset.evaluation_trees(batches[1])
    assert tree in ordinary and tree not in dataset.limited_trees(batches[1])


def test_the_limited_techniques_are_a_list_of_techniques_not_a_size_limit():
    assert dataset.LIMITATION_TECHNIQUES == ("T1003.001",)
    import inspect
    source = inspect.getsource(dataset.Tree.limited.fget)
    assert "LIMITATION_TECHNIQUES" in source and "n_events" not in source and "MIN_SNAPSHOT_EVENTS" not in source


# ---- pools listed in excluded_from_ml_pools are skipped, for training and for evaluation ------
# None of these tests trains anything: they stop at the first call to the trainer.

FIM_POOL = ("fim-test-only",)


class StopBeforeTraining(RuntimeError):
    pass


def plan_file(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "recording_tests.json"
    path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return path


def add_fim_session(export: Path, name="s1-fim", batch=1, labels=True, malicious=False) -> None:
    """A script that changes persistence items. Its Run-key writes look like T1547.001."""
    make_session(export, name, attack_recording(), batch=batch, pool="fim-test-only",
                 technique="T1547.001" if malicious else None, malicious=malicious)
    if not labels:
        (export / f"batch-{batch}-labels" / name / "labels.csv").unlink()


def test_the_pool_list_is_read_from_recording_tests_json(tmp_path):
    path = plan_file(tmp_path, {"tests": [], "excluded_from_ml_pools": ["fim-test-only"]})
    assert dataset.load_excluded_pools(path) == ("fim-test-only",)
    assert dataset.load_excluded_pools(plan_file(tmp_path, {"excluded_from_ml_pools": []})) == ()


@pytest.mark.parametrize("content, message", [
    ("{not json", "cannot read"),
    ({"tests": []}, "no excluded_from_ml_pools"),
    ([], "no excluded_from_ml_pools"),
    ({"excluded_from_ml_pools": "fim-test-only"}, "list of pool names"),
    ({"excluded_from_ml_pools": ["fim-test-only", 3]}, "list of pool names"),
    ({"excluded_from_ml_pools": [""]}, "list of pool names"),
])
def test_a_bad_or_incomplete_recording_tests_file_stops_the_run(tmp_path, content, message):
    with pytest.raises(DatasetError, match=message):
        dataset.load_excluded_pools(plan_file(tmp_path, content))


def test_a_missing_recording_tests_file_stops_the_run_and_says_where_it_lives(tmp_path):
    with pytest.raises(DatasetError, match="track-a/fim-session"):
        dataset.load_excluded_pools(tmp_path / "nowhere.json")


def test_a_session_of_an_excluded_pool_is_skipped_by_name_and_needs_no_labels(export):
    add_fim_session(export, labels=False)
    batches, folders, no_labels, left_out = train.prepare(spec(export), only_labelled=False, excluded_pools=FIM_POOL)
    assert left_out == {1: [{"session": "s1-fim", "pool": "fim-test-only"}], 2: [], 3: []}
    assert "s1-fim" not in {p.name for p in folders[1]} and "s1-fim" not in {t.row["session_id"] for t in batches[1]}
    assert no_labels == {}  # only_labelled was off, and the skipped session is not an "unlabelled" one either
    _, _, no_labels, _ = train.prepare(spec(export), only_labelled=True, excluded_pools=FIM_POOL)
    assert all("s1-fim" not in names for names in no_labels.values())


def test_without_the_exclusion_such_a_session_is_not_loaded_as_ordinary_data(export):
    add_fim_session(export)  # it has labels, and a pool that nothing lists as excluded
    with pytest.raises(DatasetError, match=r"pool 'fim-test-only' is neither a known pool"):
        dataset.load_batch(1, export / "batch-1", export / "batch-1-labels")
    with pytest.raises(DatasetError, match="fim-test-only"):
        train.prepare(spec(export), only_labelled=False, excluded_pools=())
    # A pool nobody has heard of stops the run the same way.
    make_session(export, "s2-odd", benign_recording(), batch=2, pool="some-new-pool", malicious=False)
    with pytest.raises(DatasetError, match="some-new-pool"):
        dataset.load_batch(2, export / "batch-2", export / "batch-2-labels")


def test_an_unreadable_session_pool_is_never_assumed_harmless(export):
    (export / "batch-1" / "s1-attack" / "session.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(DatasetError, match="cannot read the pool"):
        train.prepare(spec(export), only_labelled=False, excluded_pools=FIM_POOL)


def test_an_excluded_session_never_reaches_training_or_recall(export):
    """An attack-looking one (technique T1547.001, labelled test events) in batch 1, listed as excluded."""
    reference = {n: dataset.load_batch(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2, 3)}
    add_fim_session(export, malicious=True)
    batches, _, _, left_out = train.prepare(spec(export), only_labelled=False, excluded_pools=FIM_POOL)
    assert left_out[1] == [{"session": "s1-fim", "pool": "fim-test-only"}]
    everywhere = []
    for n in (1, 2, 3):
        ordinary, held_out = dataset.evaluation_trees(batches[n])
        everywhere += batches[n] + ordinary + held_out + dataset.limited_trees(batches[n])
    for include in (False, True):
        everywhere += dataset.training_trees(batches, [1, 2, 3], include_limited=include)
    assert "s1-fim" not in {t.row["session_id"] for t in everywhere}
    assert "s1-fim" not in {r["session_id"] for r in dataset.snapshot_training_rows(dataset.training_trees(batches, [1, 2, 3]))}
    # The sets are exactly what they are without that session: nothing of it moved a count.
    assert dataset.balance_table(batches) == dataset.balance_table(reference)
    for n in (1, 2, 3):
        assert [t.row["tree_id"] for t in batches[n]] == [t.row["tree_id"] for t in reference[n]]


def test_the_trainer_is_never_handed_a_row_of_an_excluded_session(export, monkeypatch):
    add_fim_session(export, malicious=True)
    seen = []

    def stop(rows):
        seen.append({r["session_id"] for r in rows})
        raise StopBeforeTraining

    monkeypatch.setattr(train.model_module, "train", stop)
    with pytest.raises(StopBeforeTraining):
        train.run(spec(export), None, excluded_pools=FIM_POOL)
    assert seen and "s1-fim" not in seen[0] and seen[0]  # the first training call, in the threshold's inner fold
    # Told nothing about the pool, the run stops before any training, instead of training on it.
    seen.clear()
    with pytest.raises(DatasetError, match="fim-test-only"):
        train.run(spec(export), None)
    assert seen == []


def test_the_report_lists_the_skipped_sessions_by_name(export):
    add_fim_session(export)
    batches, _, skipped, left_out = train.prepare(spec(export), only_labelled=False, excluded_pools=FIM_POOL)
    source = {"path": "recording_tests.json", "sha256": "0" * 64}
    header, all_training = train.report_header(batches, skipped, left_out, False, FIM_POOL, source)
    assert header["excluded_from_ml_pools"] == ["fim-test-only"] and header["excluded_pools_source"] == source
    assert header["sessions_left_out_for_an_excluded_pool"] == {"1": [{"session": "s1-fim", "pool": "fim-test-only"}]}
    assert "s1-fim" not in {t.row["session_id"] for t in all_training}
    lines = train.left_out_lines(header)
    assert any("Batch 1: 1 session(s) left out for an excluded pool: s1-fim (pool fim-test-only)" in line for line in lines)
    assert any("excluded_from_ml_pools" in line and "fim-test-only" in line for line in lines)
    none_given, _ = train.report_header(batches, skipped, left_out, False, (), None)
    assert any("none given" in line for line in train.left_out_lines(none_given))


def test_the_cli_reads_the_pool_list_and_stops_without_a_usable_file(export, tmp_path, monkeypatch, capsys):
    batches = ["--batch", "1", str(export / "batch-1"), str(export / "batch-1-labels"),
               "--batch", "2", str(export / "batch-2"), str(export / "batch-2-labels"),
               "--batch", "3", str(export / "batch-3"), str(export / "batch-3-labels")]
    got = {}

    def capture(spec_, save_to, only_labelled=False, include_limited=False, pools=(), source=None):
        got.update(pools=pools, source=source)
        raise StopBeforeTraining

    monkeypatch.setattr(train, "run", capture)
    plan = plan_file(tmp_path, {"tests": [], "excluded_from_ml_pools": ["fim-test-only"]})
    with pytest.raises(StopBeforeTraining):
        train.main([*batches, "--recording-tests", str(plan), "--out", str(tmp_path / "out")])
    assert got["pools"] == ("fim-test-only",)
    assert got["source"] == {"path": str(plan), "sha256": model.sha256_of(plan)}
    # No file, or a file without the key: it stops, and never trains on a guess.
    got.clear()
    assert train.main([*batches, "--recording-tests", str(tmp_path / "missing.json"), "--out", str(tmp_path / "o2")]) == 1
    assert "track-a/fim-session" in capsys.readouterr().err
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"tests": []}), encoding="utf-8")
    assert train.main([*batches, "--recording-tests", str(old), "--out", str(tmp_path / "o3")]) == 1
    assert "no excluded_from_ml_pools" in capsys.readouterr().err
    assert got == {}  # run() was never reached


def test_the_default_recording_tests_path_is_track_as_file():
    assert dataset.DEFAULT_RECORDING_TESTS.name == "recording_tests.json"
    assert dataset.DEFAULT_RECORDING_TESTS.parent.name == "config" and dataset.DEFAULT_RECORDING_TESTS.parent.parent.name == "agent"
    # The pool name is not written into the loader: the file is the single source of the list.
    import inspect
    logic = (inspect.getsource(dataset.load_excluded_pools) + inspect.getsource(dataset.session_folders)
             + inspect.getsource(dataset.load_batch) + inspect.getsource(dataset.pool_excluded_sessions)
             + inspect.getsource(train.prepare))
    assert "fim-test-only" not in logic and "fim-test-only" not in dataset.KNOWN_POOLS
