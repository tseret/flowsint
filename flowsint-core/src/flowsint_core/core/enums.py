from enum import Enum


class EventLevel(str, Enum):
    # Standard log levels
    INFO = "INFO"
    WARNING = "WARNING"
    FAILED = "FAILED"
    SUCCESS = "SUCCESS"
    DEBUG = "DEBUG"
    # Enricher-specific statuses
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    GRAPH_APPEND = "GRAPH_APPEND"

    @property
    def lowercase(self) -> str:
        """Get the lowercase version of the enum value"""
        return self.value.lower()
