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
    for batch in (1, 2):
        make_session(tmp_path, f"s{batch}-attack", attack_recording(), batch=batch)
        make_session(tmp_path, f"s{batch}-benign", benign_recording(), batch=batch, malicious=False)
    make_session(tmp_path, "s2-heldout", attack_recording(), batch=2, pool="held-out", technique="T1218.011")
    return tmp_path


def spec(export: Path):
    return [(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2)]


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
    assert [(f["train_batches"], f["test_batch"]) for f in report["folds"]] == [([2], 1), ([1], 2)]
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
    assert all(w in text for w in ("precision", "recall", "FPR", "PRELIMINARY", "skew", "alert-time"))


def test_the_saved_model_is_trained_without_held_out_sessions(export, tmp_path):
    out = tmp_path / "models"
    train.run(spec(export), out)
    meta = json.loads((out / model.META_FILE).read_text(encoding="utf-8"))
    assert "s2-heldout" not in meta["trained_sessions"]
    assert meta["held_out_techniques_excluded"] == ["T1053.005", "T1685", "T1218.011"]
    assert meta["trained_on_batches"] == [1, 2] and "PRELIMINARY" in meta["status"]
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
    batches = {n: dataset.load_batch(n, export / f"batch-{n}", export / f"batch-{n}-labels") for n in (1, 2)}
    rows = [t.row for t in dataset.training_trees(batches, [1, 2])]
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


def test_three_batches_give_three_folds_each_testing_an_unseen_batch(export):
    make_session(export, "s3-attack", attack_recording(), batch=3)
    make_session(export, "s3-benign", benign_recording(), batch=3, malicious=False)
    make_session(export, "s3-heldout", attack_recording(), batch=3, pool="held-out", technique="T1053.005")
    three = spec(export) + [(3, export / "batch-3", export / "batch-3-labels")]
    report = train.run(three, None)
    assert [(f["train_batches"], f["test_batch"]) for f in report["folds"]] == [([2, 3], 1), ([1, 3], 2), ([1, 2], 3)]
    for fold in report["folds"]:
        assert fold["test_batch"] not in fold["train_batches"]
    held = {f["test_batch"]: f["models"]["snapshots"]["held_out_techniques"].get("positives", 0) for f in report["folds"]}
    assert held == {1: 0, 2: 1, 3: 1}  # a held-out session is only ever on the test side
