from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from .base import ORMBase


class CaseItemCreate(BaseModel):
    kind: Literal["comment", "question", "finding"]
    body: str = Field(min_length=1, max_length=20000)
    assignee_id: UUID | None = None
    sketch_id: UUID | None = None
    target_kind: Literal["entity", "relationship"] | None = None
    target_id: str | None = Field(default=None, max_length=256)
    evidence: str = Field(default="", max_length=20000)
    assessment: str = Field(default="", max_length=20000)

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if not self.body.strip():
            raise ValueError("Body must not be blank")
        if self.target_kind or self.target_id:
            if not self.target_kind or not self.target_id or not self.sketch_id:
                raise ValueError(
                    "A graph target requires sketch_id, target_kind, and target_id"
                )
        return self


class CaseItemUpdate(BaseModel):
    version: int = Field(ge=1)
    body: str | None = Field(default=None, min_length=1, max_length=20000)
    assignee_id: UUID | None = None
    evidence: str | None = Field(default=None, max_length=20000)
    assessment: str | None = Field(default=None, max_length=20000)
    status: Literal["open", "resolved"] | None = None
    decision: Literal["pending", "accepted", "rejected"] | None = None

    @model_validator(mode="after")
    def validate_values(self) -> Self:
        for name in self.model_fields_set - {"assignee_id"}:
            if getattr(self, name) is None:
                raise ValueError(f"{name} must not be null")
        if self.body is not None and not self.body.strip():
            raise ValueError("Body must not be blank")
        return self


class CaseItemRead(ORMBase):
    id: UUID
    investigation_id: UUID
    author_id: UUID | None
    assignee_id: UUID | None
    reviewer_id: UUID | None
    sketch_id: UUID | None
    target_kind: str | None
    target_id: str | None
    kind: str
    body: str
    evidence: str
    assessment: str
    decision: str
    status: str
    version: int
    created_at: datetime
    updated_at: datetime


class CaseActivityRead(ORMBase):
    id: UUID
    actor_id: UUID | None
    actor_name: str
    action: str
    item_id: UUID | None
    details: dict
    created_at: datetime
