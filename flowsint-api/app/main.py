import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Routes to be included
from app.api.routes import (
    analysis,
    auth,
    chat,
    chatgpt_subscription,
    copilot,
    custom_types,
    diagnostics,
    enricher_templates,
    enrichers,
    events,
    flows,
    investigations,
    keys,
    scan,
    sketches,
    types,
)

# Comma-separated list of allowed origins, e.g. "https://app.example.com,https://staging.example.com"
# Falls back to localhost dev origin when unset. Never use "*" with allow_credentials=True.
origins = [
    o.strip()
    for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]


app = FastAPI(ignore_trailing_slash=True, redirect_slashes=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class OAuthCallbackLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) == 5:
            path = record.args[2]
            if (
                isinstance(path, str)
                and path.split("?", 1)[0] == "/api/chatgpt-subscription/callback"
            ):
                record.args = (
                    *record.args[:2],
                    path.split("?", 1)[0],
                    *record.args[3:],
                )
        return True


logging.getLogger("uvicorn.access").addFilter(OAuthCallbackLogFilter())


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint for Docker healthcheck"""
    return {"status": "ok"}


app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(sketches.router, prefix="/api/sketches", tags=["sketches"])
app.include_router(
    investigations.router, prefix="/api/investigations", tags=["investigations"]
)
app.include_router(enrichers.router, prefix="/api/enrichers", tags=["enrichers"])
app.include_router(flows.router, prefix="/api/flows", tags=["flows"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(analysis.router, prefix="/api/analyses", tags=["analyses"])
app.include_router(chat.router, prefix="/api/chats", tags=["chats"])
app.include_router(
    chatgpt_subscription.router,
    prefix="/api/chatgpt-subscription",
    tags=["chatgpt-subscription"],
)
app.include_router(copilot.router, prefix="/api/copilot", tags=["copilot"])
app.include_router(scan.router, prefix="/api/scans", tags=["scans"])
app.include_router(keys.router, prefix="/api/keys", tags=["keys"])
app.include_router(diagnostics.router, prefix="/api/diagnostics", tags=["diagnostics"])
app.include_router(types.router, prefix="/api/types", tags=["types"])
app.include_router(
    custom_types.router, prefix="/api/custom-types", tags=["custom-types"]
)
app.include_router(
    enricher_templates.router,
    prefix="/api/enrichers/templates",
    tags=["enricher-templates"],
)
