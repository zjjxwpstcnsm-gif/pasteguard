#!/usr/bin/env python3
"""Structural checks that do not require a Rust toolchain."""

from __future__ import annotations

import re
import sqlite3
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_workspace() -> None:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    assert manifest["workspace"]["package"]["version"] == "0.1.0-alpha.4"
    members = manifest["workspace"]["members"]
    for member in members:
        crate = ROOT / member
        assert (crate / "Cargo.toml").is_file(), member
        assert (crate / "src").is_dir(), member
        assert any((crate / "src" / name).is_file() for name in ("lib.rs", "main.rs")), member


def check_rust_modules() -> None:
    module_pattern = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M)
    for entry in ROOT.glob("crates/*/src/lib.rs"):
        source = entry.read_text(encoding="utf-8")
        for module in module_pattern.findall(source):
            flat = entry.parent / f"{module}.rs"
            nested = entry.parent / module / "mod.rs"
            assert flat.exists() or nested.exists(), f"missing module {module} declared by {entry}"
    main = ROOT / "crates/punctual-app/src/main.rs"
    source = main.read_text(encoding="utf-8")
    for module in module_pattern.findall(source):
        assert (main.parent / f"{module}.rs").exists(), f"missing app module {module}"


def check_migrations() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute("PRAGMA foreign_keys = ON")
    for migration in sorted((ROOT / "crates/punctual-storage/migrations").glob("*.sql")):
        connection.executescript(migration.read_text(encoding="utf-8"))
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {"click_tasks", "execution_logs"}.issubset(tables)
    connection.close()


def check_milestone_contract() -> None:
    app = (ROOT / "crates/punctual-app/src/dashboard.rs").read_text(encoding="utf-8")
    editor = (ROOT / "crates/punctual-app/src/editor.rs").read_text(encoding="utf-8")
    browser = (ROOT / "crates/punctual-browser/src/chromium.rs").read_text(encoding="utf-8")
    engine_loop = (ROOT / "crates/punctual-engine/src/engine.rs").read_text(encoding="utf-8")
    engine = (ROOT / "crates/punctual-engine/src/worker.rs").read_text(encoding="utf-8")
    messages = (ROOT / "crates/punctual-core/src/message.rs").read_text(encoding="utf-8")
    probe = (ROOT / "scripts/probe_target.js").read_text(encoding="utf-8")
    detector = (ROOT / "scripts/detect_buttons.js").read_text(encoding="utf-8")
    duplicate_fixture = (ROOT / "fixtures/multi-buy.html").read_text(encoding="utf-8")
    prepared_fixture = (ROOT / "fixtures/prepared-click.html").read_text(encoding="utf-8")
    workflow_test = (ROOT / "scripts/workflow-smoke-test.py").read_text(encoding="utf-8")

    forbidden = ("create_demo_task", "advance_selected", "推进演示状态")
    for value in forbidden:
        assert value not in app, f"alpha.1 demo behavior remains: {value}"

    for required in (
        "DetectTargets",
        "ValidateManualTarget",
        "HighlightTarget",
        "SaveTask",
        "LoadExecutionLogs",
    ):
        assert required in messages, required

    for required in (
        "resolve_target",
        "dispatch_at_deadline",
        "verify_after_click",
        "save_task_and_log",
        "completion_baseline",
        "&baseline",
    ):
        assert required in engine, required

    for required in ("inspected_url", "validated_manual_text", "页面 URL 已改变"):
        assert required in editor, required

    assert "completion_baseline" in browser
    assert "CompletionBaseline" in browser
    assert "pageUrl: window.location.href" in probe
    assert "visibleText:" in probe
    assert "presentSelectors" in probe
    assert "scrollIntoView !== false" in probe
    assert "queryRoot.querySelectorAll" in detector
    assert "matches.length === 1 && matches[0] === element" in detector
    assert duplicate_fixture.count('<button data-testid="buy-action"') == 2
    assert "prepared-submit" in prepared_fixture
    assert '"scrollIntoView": False' in workflow_test
    assert "prepare_target" in engine
    assert "data-clicked-product" in workflow_test
    assert "len(set(selector_hints)) == 2" in workflow_test
    assert "TaskStatus::Executing" in engine_loop
    assert "不能编辑或重新安排" in engine_loop
    assert "不能删除" in engine_loop

    for required in (
        "overflow_y_scrollbar",
        "ClipboardItem::new_string",
        "copyable_info_block",
        "candidate-list-scroll",
        "task-list-scroll",
        "details-scroll",
        "editor-scroll",
    ):
        assert required in app, required


def main() -> None:
    check_workspace()
    check_rust_modules()
    check_migrations()
    check_milestone_contract()
    print("project structure, migrations and alpha.3 product-polish contract: OK")


if __name__ == "__main__":
    main()
