from celery import Celery

from .config import settings

celery = Celery(
    "flowsint",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "flowsint_core.tasks.event",
        "flowsint_core.tasks.enricher",
        "flowsint_core.tasks.flow",
        "flowsint_core.tasks.diagnostics",
        "flowsint_core.tasks.agent",
    ],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    worker_max_tasks_per_child=1000,
    worker_prefetch_multiplier=4,  # Allow each worker to prefetch up to 4 tasks
    # Agents wait on their own run_enricher tasks; a separate queue and worker
    # keep them from occupying the threads those child tasks need.
    task_routes={"run_investigation_agent": {"queue": "agents"}},
)
