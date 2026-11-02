"""Evidence of redaction for a data-protection officer.

When ``KESTRAL_EVIDENCE=on``, every redaction of a gateway request, of a
reply in ``pii`` mode, and of a ``/pii`` call writes rows to
``redaction_events``: the request id, direction, message role, entity and
how many values were redacted. The values themselves are never stored.

Rows are chained: each holds a hash of the one before, so a deleted or
edited row shows up in :meth:`EvidenceLog.check_chain`.

With ``KESTRAL_EVIDENCE_DIGEST=on`` each row also holds keyed digests of
its values, ``HMAC-SHA-256(key, request_id, entity, value)``, so an officer
can confirm "value X was redacted in request R" (:meth:`EvidenceLog.matches`)
without the log holding X. The request id is part of the digest, so the
same person cannot be linked across requests. Phone numbers and Emirates IDs
have few enough possible values that a leaked key would reverse every digest:
keep the key in a secret store, not beside the database, and retire keys by
destroying them (the digests made with them become meaningless).
"""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import hmac
import io
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from kestral.persistence.database import DatabaseManager

# Rows written for one request at most; the rest are summed into one row.
MAX_ROWS_PER_REQUEST = 64
# Digests kept per row at most.
MAX_DIGESTS_PER_ROW = 256
_GENESIS = "0" * 64
_NAME = re.compile(r"^[a-z0-9_.-]{1,64}$")
_FIELDS = ("id", "request_id", "timestamp", "direction", "role", "entity", "count", "policy")


@dataclass(frozen=True)
class KeyRing:
    """Digest keys by id; the first is the one used for new rows."""

    keys: tuple[tuple[str, bytes], ...]

    @property
    def active(self) -> tuple[str, bytes]:
        return self.keys[0]

    def get(self, key_id: str) -> bytes | None:
        return dict(self.keys).get(key_id)

    @classmethod
    def from_env(cls, raw: str) -> KeyRing:
        """``id:base64key[,id:base64key ...]``, newest first. Keys of 32 bytes or more."""
        keys: list[tuple[str, bytes]] = []
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            key_id, _, encoded = item.partition(":")
            if not _NAME.match(key_id):
                raise ValueError(f"evidence key id {key_id!r} must match {_NAME.pattern}")
            try:
                key = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"evidence key {key_id!r} is not base64") from exc
            if len(key) < 32:
                raise ValueError(f"evidence key {key_id!r} must be at least 32 bytes")
            keys.append((key_id, key))
        if not keys:
            raise ValueError("no evidence keys given")
        return cls(tuple(keys))


def digest(key: bytes, request_id: str, entity: str, value: str) -> str:
    message = "\x1f".join((request_id, entity, value)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _row_hash(prev: str, row: dict[str, Any]) -> str:
    canonical = json.dumps(
        [prev] + [row.get(f) for f in (*_FIELDS, "key_id", "value_digests")],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _csv_cell(value: Any) -> Any:
    # A cell starting with = + - @ or a control character is a formula in
    # a spreadsheet.
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


class EvidenceLog:
    def __init__(self, db: DatabaseManager, keys: KeyRing | None = None) -> None:
        self._db = db
        self._keys = keys

    @property
    def digests(self) -> bool:
        return self._keys is not None

    def record(
        self,
        request_id: str,
        direction: str,
        policy: str,
        found: Iterable[tuple[str, str, str | None]],
    ) -> int:
        """Write rows for ``found``: ``(role, entity, value)`` per redacted value.

        ``value`` is used only for the digest, and may be None when digests
        are off. Returns the number of rows written.
        """
        groups: dict[tuple[str, str], list[str | None]] = {}
        for role, entity, value in found:
            groups.setdefault((role, entity), []).append(value)
        if not groups:
            return 0
        items = sorted(groups.items())
        if len(items) > MAX_ROWS_PER_REQUEST:
            head = items[: MAX_ROWS_PER_REQUEST - 1]
            rest = [v for _, values in items[MAX_ROWS_PER_REQUEST - 1 :] for v in values]
            items = [*head, (("*", "*"), rest)]
        now = datetime.now(timezone.utc).isoformat()
        key_id, key = self._keys.active if self._keys else (None, None)
        with self._db.connection() as conn:
            last = conn.execute(
                "SELECT row_hash FROM redaction_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = last["row_hash"] if last else _GENESIS
            for (role, entity), values in items:
                digests = None
                if key is not None:
                    digests = json.dumps(
                        sorted(
                            {
                                digest(key, request_id, entity, v)
                                for v in values[:MAX_DIGESTS_PER_ROW]
                                if v is not None
                            }
                        )
                    )
                row: dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "request_id": request_id,
                    "timestamp": now,
                    "direction": direction,
                    "role": role,
                    "entity": entity,
                    "count": len(values),
                    "policy": policy,
                    "key_id": key_id,
                    "value_digests": digests,
                }
                row["prev_hash"] = prev
                row["row_hash"] = prev = _row_hash(prev, row)
                conn.execute(
                    "INSERT INTO redaction_events (id, request_id, timestamp, direction, role,"
                    " entity, count, policy, key_id, value_digests, prev_hash, row_hash)"
                    " VALUES (:id, :request_id, :timestamp, :direction, :role, :entity, :count,"
                    " :policy, :key_id, :value_digests, :prev_hash, :row_hash)",
                    row,
                )
            conn.commit()
        return len(items)

    def rows(self, since: str | None = None, until: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM redaction_events WHERE 1=1"
        args: list[str] = []
        if since:
            query += " AND timestamp >= ?"
            args.append(since)
        if until:
            query += " AND timestamp < ?"
            args.append(until)
        with self._db.connection() as conn:
            return [dict(r) for r in conn.execute(query + " ORDER BY seq", args).fetchall()]

    def check_chain(self) -> tuple[bool, int]:
        """Whether every row's hash matches its content and the row before.

        Returns ``(ok, rows checked)``. Rows removed by :meth:`prune` from the
        start of the log are expected; the first remaining row is the anchor.
        """
        rows = self.rows()
        prev = rows[0]["prev_hash"] if rows else _GENESIS
        for row in rows:
            if row["prev_hash"] != prev or _row_hash(prev, row) != row["row_hash"]:
                return False, len(rows)
            prev = row["row_hash"]
        return True, len(rows)

    def matches(self, request_id: str, entity: str, value: str, actor: str) -> bool:
        """Was ``value`` redacted as ``entity`` in ``request_id``? The check is audited."""
        found = False
        with self._db.connection() as conn:
            for row in conn.execute(
                "SELECT key_id, value_digests FROM redaction_events"
                " WHERE request_id = ? AND entity = ?",
                (request_id, entity),
            ).fetchall():
                key = self._keys.get(row["key_id"]) if self._keys and row["key_id"] else None
                if key is None or not row["value_digests"]:
                    continue
                if digest(key, request_id, entity, value) in json.loads(row["value_digests"]):
                    found = True
                    break
        self._audit("verify", actor, {"request_id": request_id, "entity": entity})
        return found

    def export(
        self, fmt: str, actor: str, since: str | None = None, until: str | None = None
    ) -> str:
        """Rows as JSON lines or CSV, without digests. The export is audited."""
        rows = self.rows(since, until)
        fields = [*_FIELDS, "prev_hash", "row_hash"]
        if fmt == "jsonl":
            text = "".join(json.dumps({f: r[f] for f in fields}) + "\n" for r in rows)
        elif fmt == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(fields)
            for r in rows:
                writer.writerow([_csv_cell(r[f]) for f in fields])
            text = buffer.getvalue()
        else:
            raise ValueError("format must be jsonl or csv")
        self._audit("export", actor, {"from": since, "to": until, "rows": len(rows), "format": fmt})
        return text

    def prune(self, retention_days: int, actor: str) -> int:
        with self._db.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM redaction_events WHERE timestamp < ?",
                (
                    datetime.fromtimestamp(
                        datetime.now(timezone.utc).timestamp() - retention_days * 86400,
                        timezone.utc,
                    ).isoformat(),
                ),
            )
            conn.commit()
            deleted = cursor.rowcount
        self._audit("prune", actor, {"retention_days": retention_days, "rows": deleted})
        return deleted

    def _audit(self, action: str, actor: str, detail: dict[str, Any]) -> None:
        with self._db.connection() as conn:
            conn.execute(
                "INSERT INTO evidence_audit (id, timestamp, action, actor, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    datetime.now(timezone.utc).isoformat(),
                    action,
                    actor,
                    json.dumps(detail),
                ),
            )
            conn.commit()


def from_env(env: dict[str, str], db: DatabaseManager, db_path: str | None) -> EvidenceLog | None:
    """The evidence log configured by ``KESTRAL_EVIDENCE*``, or None when off."""
    if env.get("KESTRAL_EVIDENCE", "").strip().lower() not in ("1", "on", "true"):
        return None
    keys = None
    if env.get("KESTRAL_EVIDENCE_DIGEST", "").strip().lower() in ("1", "on", "true"):
        keys = KeyRing.from_env(env.get("KESTRAL_EVIDENCE_KEYS", ""))
    if db_path:
        # The database holds who was redacted when; only the service reads it.
        for path in (db_path, db_path + "-wal", db_path + "-shm"):
            if os.path.exists(path):
                os.chmod(path, 0o600)
    return EvidenceLog(db, keys)


def required(env: dict[str, str]) -> bool:
    """KESTRAL_EVIDENCE_REQUIRED: refuse a request whose evidence cannot be written."""
    return env.get("KESTRAL_EVIDENCE_REQUIRED", "").strip().lower() in ("1", "on", "true")


__all__ = [
    "MAX_ROWS_PER_REQUEST",
    "EvidenceLog",
    "KeyRing",
    "digest",
    "from_env",
    "required",
]
