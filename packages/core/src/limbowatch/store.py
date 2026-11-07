"""Tracker state: SQLAlchemy 2.0 (SQLite at runtime, Postgres-compatible types).

Durable state is exported as sorted JSON Lines (one file per table) so it can be committed to a
data branch and diffed. Nothing stored here holds advisory text or personal data: advisories are
stored as normalized `RepoAdvisory` models (FINDINGS F-047, F-059).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Base(DeclarativeBase):
    pass


class Repo(Base):
    __tablename__ = "repos"
    full_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)  # why it's on the watchlist
    first_seen: Mapped[str] = mapped_column(String(32))
    last_polled_at: Mapped[str | None] = mapped_column(String(32), default=None)
    poll_status: Mapped[int | None] = mapped_column(Integer, default=None)
    etag: Mapped[str | None] = mapped_column(String(200), default=None)
    etag_token: Mapped[str | None] = mapped_column(String(32), default=None)  # token fingerprint (F-058)
    advisory_count: Mapped[int] = mapped_column(Integer, default=0)
    released_at: Mapped[str | None] = mapped_column(String(32), default=None)  # latest release of its package seen


class Advisory(Base):
    __tablename__ = "advisories"
    ghsa_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    repo: Mapped[str] = mapped_column(String(200), index=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)  # RepoAdvisory, factual fields only
    first_seen: Mapped[str] = mapped_column(String(32))
    last_seen: Mapped[str] = mapped_column(String(32))
    gone_since: Mapped[str | None] = mapped_column(String(32), default=None)  # no longer listed by the repo


class Reviewed(Base):
    __tablename__ = "reviewed"
    ghsa_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True, default=None)
    reviewed_at: Mapped[str | None] = mapped_column(String(32), default=None)
    origin_repo: Mapped[str | None] = mapped_column(String(200), index=True, default=None)


class Cve(Base):
    __tablename__ = "cves"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)  # CveInfo
    fetched_at: Mapped[str] = mapped_column(String(32))


class Nvd(Base):
    __tablename__ = "nvd"
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(40))
    enriched: Mapped[bool] = mapped_column(Boolean)
    fetched_at: Mapped[str] = mapped_column(String(32))


class FactSnapshot(Base):
    __tablename__ = "facts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ghsa_id: Mapped[str] = mapped_column(String(32), index=True)
    observed_at: Mapped[str] = mapped_column(String(32))
    facts: Mapped[dict[str, Any]] = mapped_column(JSON)
    facts_hash: Mapped[str] = mapped_column(String(64))


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ghsa_id: Mapped[str] = mapped_column(String(32), index=True)
    at: Mapped[str] = mapped_column(String(32))
    event: Mapped[str] = mapped_column(String(300))


class Cursor(Base):
    __tablename__ = "cursors"
    name: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))
    updated_at: Mapped[str] = mapped_column(String(32))


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    started_at: Mapped[str] = mapped_column(String(32))
    finished_at: Mapped[str | None] = mapped_column(String(32), default=None)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


TABLES: list[type[Base]] = [Repo, Advisory, Reviewed, Cve, Nvd, FactSnapshot, Event, Cursor, Run]


class Store:
    def __init__(self, url: str = "sqlite://") -> None:
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with Session(self.engine, expire_on_commit=False) as s:
            yield s
            s.commit()

    # -------------------------------------------------- cursors
    def cursor(self, name: str) -> str | None:
        with self.session() as s:
            c = s.get(Cursor, name)
            return c.value if c else None

    def set_cursor(self, name: str, value: str) -> None:
        with self.session() as s:
            s.merge(Cursor(name=name, value=value, updated_at=now_iso()))

    # -------------------------------------------------- facts
    def latest_facts(self) -> dict[str, dict[str, Any]]:
        with self.session() as s:
            last = select(FactSnapshot.ghsa_id, func.max(FactSnapshot.id).label("mid")).group_by(FactSnapshot.ghsa_id)
            sub = last.subquery()
            rows = s.execute(select(FactSnapshot).join(sub, FactSnapshot.id == sub.c.mid)).scalars()
            return {r.ghsa_id: r.facts for r in rows}

    # -------------------------------------------------- persistence
    def export_jsonl(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        with self.session() as s:
            for table in TABLES:
                cols = [c.name for c in table.__table__.columns]
                rows = [{c: getattr(r, c) for c in cols} for r in s.execute(select(table)).scalars()]
                rows.sort(key=lambda r: json.dumps([r[c] for c in cols[:1]], default=str))
                path = directory / f"{table.__tablename__}.jsonl"
                tmp = path.with_suffix(".jsonl.tmp")
                with tmp.open("w") as f:
                    for row in rows:
                        f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                tmp.replace(path)

    def import_jsonl(self, directory: Path) -> None:
        with self.session() as s:
            for table in TABLES:
                path = directory / f"{table.__tablename__}.jsonl"
                if not path.exists():
                    continue
                with path.open() as f:
                    s.add_all(table(**json.loads(line)) for line in f if line.strip())
