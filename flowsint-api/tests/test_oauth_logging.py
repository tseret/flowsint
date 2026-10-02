import logging

from app.main import OAuthCallbackLogFilter


def test_callback_query_is_not_logged():
    record = logging.LogRecord(
        "uvicorn.access",
        20,
        "",
        0,
        "%s %s %s %s %s",
        (
            "127.0.0.1",
            "GET",
            "/api/chatgpt-subscription/callback?code=private-code&state=private-state",
            "1.1",
            303,
        ),
        None,
    )
    assert OAuthCallbackLogFilter().filter(record)
    assert "private-code" not in record.getMessage()
    assert "private-state" not in record.getMessage()
    assert "/api/chatgpt-subscription/callback" in record.getMessage()
