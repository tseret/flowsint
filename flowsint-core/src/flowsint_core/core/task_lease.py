"""Process-crash-safe task exclusion using the existing PostgreSQL database."""

import hashlib
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import text
from sqlalchemy.orm import Session


@contextmanager
def task_lease(session: Session, task_id: str) -> Iterator[bool]:
    key = int.from_bytes(
        hashlib.blake2b(task_id.encode(), digest_size=8).digest(), "big", signed=True
    )
    # A dedicated transaction keeps the lock across progress commits and releases
    # it on connection loss; an expiring Redis lease could admit a live worker.
    with session.get_bind().engine.connect() as connection:
        with connection.begin():
            yield bool(
                connection.execute(
                    text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": key}
                ).scalar()
            )
