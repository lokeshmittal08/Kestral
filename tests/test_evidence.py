"""Redaction evidence: rows without values, chained, audited (spec P1.6)."""

from __future__ import annotations

import base64
import json
import sqlite3

import httpx
import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from kestral import api
from kestral.evidence import MAX_ROWS_PER_REQUEST, EvidenceLog, KeyRing, from_env
from kestral.gateway import Gateway
from kestral.persistence.database import DatabaseManager
from kestral.persistence.migrations import MIGRATIONS
from kestral.request_redaction import Policy
from tests.test_gateway import Upstream, chat

PHONE = "050 123 4567"
EID = "784-1990-1234567-6"
KEY = "k1:" + base64.b64encode(b"k" * 32).decode()


@pytest.fixture()
def db(tmp_path):
    manager = DatabaseManager(str(tmp_path / "kestral.db"))
    yield manager
    manager.close()


def _found():
    return [("user", "phone", PHONE), ("user", "phone", "0551234567"), ("tool", "emirates_id", EID)]


class TestLog:
    def test_rows_are_aggregated_and_hold_no_values(self, db, tmp_path):
        log = EvidenceLog(db)
        assert log.record("req-1", "request", "mask", _found()) == 2
        rows = log.rows()
        assert {(r["role"], r["entity"], r["count"]) for r in rows} == {
            ("user", "phone", 2),
            ("tool", "emirates_id", 1),
        }
        assert all(r["value_digests"] is None for r in rows)
        raw = (tmp_path / "kestral.db").read_bytes() + (tmp_path / "kestral.db-wal").read_bytes()
        for value in (PHONE, "0551234567", EID):
            assert value.encode() not in raw

    def test_chain_detects_an_edited_row(self, db):
        log = EvidenceLog(db)
        log.record("req-1", "request", "mask", _found())
        log.record("req-2", "reply", "pii", [("assistant", "iban", "x")])
        assert log.check_chain() == (True, 3)
        with db.connection() as conn:
            conn.execute("UPDATE redaction_events SET count = 9 WHERE request_id = 'req-1'")
            conn.commit()
        assert log.check_chain()[0] is False

    def test_digests_confirm_a_value_in_one_request_only(self, db):
        log = EvidenceLog(db, KeyRing.from_env(KEY))
        log.record("req-1", "request", "tokenize", _found())
        assert log.matches("req-1", "phone", PHONE, actor="dpo")
        assert not log.matches("req-1", "phone", "050 999 9999", actor="dpo")
        assert not log.matches("req-2", "phone", PHONE, actor="dpo")
        with db.connection() as conn:
            audits = conn.execute("SELECT action FROM evidence_audit").fetchall()
        assert [a["action"] for a in audits] == ["verify"] * 3

    def test_export_has_no_digests_and_is_safe_in_a_spreadsheet(self, db):
        log = EvidenceLog(db, KeyRing.from_env(KEY))
        log.record("=cmd|' /C calc'!A0", "request", "mask", _found())
        csv_text = log.export("csv", actor="dpo")
        assert "value_digests" not in csv_text and "'=cmd" in csv_text
        lines = log.export("jsonl", actor="dpo").splitlines()
        assert len(lines) == 2 and "value_digests" not in json.loads(lines[0])

    def test_many_entities_are_capped(self, db):
        log = EvidenceLog(db)
        found = [("user", f"e{i}", "v") for i in range(MAX_ROWS_PER_REQUEST + 10)]
        assert log.record("req-1", "request", "mask", found) == MAX_ROWS_PER_REQUEST
        assert sum(r["count"] for r in log.rows()) == MAX_ROWS_PER_REQUEST + 10

    def test_prune_keeps_the_chain_checkable(self, db):
        log = EvidenceLog(db)
        log.record("req-1", "request", "mask", _found())
        assert log.prune(0, actor="ops") == 2
        log.record("req-2", "request", "mask", _found())
        assert log.check_chain() == (True, 2)


class TestKeysAndConfig:
    @pytest.mark.parametrize(
        "raw",
        ["", "k1:notbase64!", "k1:" + base64.b64encode(b"short").decode(), "Bad Id:" + KEY[3:]],
    )
    def test_bad_keys(self, raw):
        with pytest.raises(ValueError):
            KeyRing.from_env(raw)

    def test_off_by_default(self, db):
        assert from_env({}, db, None) is None
        log = from_env({"KESTRAL_EVIDENCE": "on"}, db, None)
        assert log is not None and not log.digests
        with pytest.raises(ValueError):
            from_env({"KESTRAL_EVIDENCE": "on", "KESTRAL_EVIDENCE_DIGEST": "on"}, db, None)


def test_migration_from_version_one_keeps_data(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(MIGRATIONS[1])
    conn.execute("INSERT INTO schema_version (version) VALUES (1)")
    conn.execute(
        "INSERT INTO scan_history (id, timestamp, input_hash, input_length, overall_score,"
        " action_taken, detectors_fired) VALUES ('s1', '2026-01-01', 'h', 1, 0.0, 'pass', '[]')"
    )
    conn.commit()
    conn.close()
    manager = DatabaseManager(str(path))
    with manager.connection() as c:
        assert c.execute("SELECT COUNT(*) AS n FROM scan_history").fetchone()["n"] == 1
        assert c.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()["v"] == 2
        c.execute("SELECT * FROM redaction_events").fetchall()
    manager.close()


@pytest.fixture(autouse=True)
def _own_limiter(monkeypatch):
    """A fresh rate limiter, so these requests do not use up the shared one."""
    from kestral.ratelimit import SlidingWindowLimiter

    monkeypatch.setattr(api, "_limiter", SlidingWindowLimiter(10_000, 60), raising=False)


@pytest.fixture(scope="module")
def client():
    with TestClient(api.app) as c:
        yield c


@pytest.fixture()
def wired(client, monkeypatch, tmp_path):
    stub = Upstream()
    api._state["upstream_transport"] = httpx.MockTransport(stub)
    monkeypatch.setenv("KESTRAL_UPSTREAM_URL", "https://provider.test/v1")
    monkeypatch.setenv("KESTRAL_UPSTREAM_API_KEY", "sk-upstream")
    original = api._state["gateway"]
    db = DatabaseManager(str(tmp_path / "evidence.db"))
    log = EvidenceLog(db)
    api._state["gateway"] = Gateway(
        original._engine, original._inspector, redact_requests=Policy(mode="mask")
    )
    api._state["evidence"] = log
    yield stub, log
    api._state["gateway"] = original
    api._state["evidence"] = None
    api._state["evidence_required"] = False
    api._state.pop("upstream_transport", None)
    db.close()


class TestApi:
    def test_gateway_request_writes_evidence(self, client, wired):
        _, log = wired
        r = chat(client, [{"role": "user", "content": f"My number is {PHONE}."}])
        assert r.status_code == 200
        rows = log.rows()
        assert [(x["request_id"], x["direction"], x["role"], x["entity"]) for x in rows] == [
            (r.headers["x-kestral-request-id"], "request", "user", "phone")
        ]

    def test_pii_endpoint_returns_the_request_id(self, client, wired):
        _, log = wired
        r = client.post("/pii/scan", json={"text": f"ID {EID}"})
        assert r.status_code == 200
        assert log.rows()[0]["request_id"] == r.headers["x-kestral-request-id"]

    def test_required_evidence_that_fails_refuses(self, client, wired, monkeypatch):
        upstream, log = wired
        api._state["evidence_required"] = True

        def broken(*args, **kwargs):
            raise RuntimeError("disk full")

        monkeypatch.setattr(log, "record", broken)
        r = chat(client, [{"role": "user", "content": f"My number is {PHONE}."}])
        assert r.status_code == 503 and r.json()["error"]["reason"] == "evidence_unavailable"
        assert not upstream.requests


def test_cli_export_and_check_chain(tmp_path):
    from kestral.cli import main

    db = DatabaseManager(str(tmp_path / "db" / "kestral.db"))
    EvidenceLog(db).record("req-1", "request", "mask", _found())
    db.close()
    runner = CliRunner()
    out = runner.invoke(main, ["--data-dir", str(tmp_path), "evidence", "export"])
    assert out.exit_code == 0 and len(out.output.splitlines()) == 2
    out = runner.invoke(main, ["--data-dir", str(tmp_path), "evidence", "check-chain"])
    assert out.exit_code == 0 and "intact: 2 rows" in out.output
