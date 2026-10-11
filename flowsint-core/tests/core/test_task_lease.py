from unittest.mock import MagicMock

import pytest

from flowsint_core.core.task_lease import task_lease


def test_lease_uses_separate_transaction_and_releases_on_failure():
    session = MagicMock()
    connection = (
        session.get_bind.return_value.engine.connect.return_value.__enter__.return_value
    )
    connection.execute.return_value.scalar.return_value = True
    with pytest.raises(RuntimeError):
        with task_lease(session, "scan-id") as acquired:
            assert acquired is True
            session.commit()
            connection.begin.return_value.__exit__.assert_not_called()
            raise RuntimeError("worker stopped")
    connection.begin.return_value.__exit__.assert_called_once()
    assert "pg_try_advisory_xact_lock" in str(connection.execute.call_args.args[0])
    first_key = connection.execute.call_args.args[1]["key"]
    with task_lease(session, "scan-id"):
        assert connection.execute.call_args.args[1]["key"] == first_key


def test_lease_reports_contention():
    session = MagicMock()
    connection = (
        session.get_bind.return_value.engine.connect.return_value.__enter__.return_value
    )
    connection.execute.return_value.scalar.return_value = False
    with task_lease(session, "scan-id") as acquired:
        assert acquired is False
