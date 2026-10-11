"""Persistent collaboration scoped to existing investigation permissions."""

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from ..models import CaseActivity, CaseItem, Profile, Sketch
from ..repositories import InvestigationRepository
from .base import BaseService
from .exceptions import (
    ConflictError,
    DatabaseError,
    NotFoundError,
    PermissionDeniedError,
)


class CollaborationService(BaseService):
    def __init__(self, db: Session):
        super().__init__(db)
        self._investigation_repo = InvestigationRepository(db)

    def items(
        self,
        investigation_id: UUID,
        user_id: UUID,
        offset: int = 0,
        sketch_id: UUID | None = None,
        target_kind: str | None = None,
        target_id: str | None = None,
    ) -> list[CaseItem]:
        self._check_permission(user_id, investigation_id, ["read"])
        query = self.db.query(CaseItem).filter_by(investigation_id=investigation_id)
        if sketch_id:
            query = query.filter_by(sketch_id=sketch_id)
        if target_kind:
            query = query.filter_by(target_kind=target_kind)
        if target_id:
            query = query.filter_by(target_id=target_id)
        return (
            query.order_by(CaseItem.created_at.desc(), CaseItem.id.desc())
            .offset(offset)
            .limit(100)
            .all()
        )

    def activity(
        self, investigation_id: UUID, user_id: UUID, offset: int = 0
    ) -> list[CaseActivity]:
        self._check_permission(user_id, investigation_id, ["read"])
        return (
            self.db.query(CaseActivity)
            .filter_by(investigation_id=investigation_id)
            .order_by(CaseActivity.created_at.desc(), CaseActivity.id.desc())
            .offset(offset)
            .limit(100)
            .all()
        )

    def record(
        self,
        investigation_id: UUID,
        user_id: UUID,
        action: str,
        item_id: UUID,
        details: dict,
    ) -> None:
        with self.db.no_autoflush:
            actor = self.db.get(Profile, user_id)
        name = (
            " ".join(filter(None, [actor.first_name, actor.last_name])) or actor.email
            if actor
            else "Deleted user"
        )
        self.db.add(
            CaseActivity(
                investigation_id=investigation_id,
                actor_id=user_id,
                actor_name=name,
                action=action,
                item_id=item_id,
                details=details,
            )
        )

    def _validate_assignment(
        self, investigation_id: UUID, assignee_id: UUID | None
    ) -> None:
        if assignee_id and not self._investigation_repo.get_user_role(
            assignee_id, investigation_id
        ):
            raise PermissionDeniedError(
                "Assignee must be an investigation collaborator"
            )

    def create(
        self, investigation_id: UUID, user_id: UUID, values: dict[str, Any]
    ) -> CaseItem:
        self._check_permission(user_id, investigation_id, ["create"])
        self._validate_assignment(investigation_id, values.get("assignee_id"))
        if values.get("sketch_id"):
            sketch = self.db.get(Sketch, values["sketch_id"])
            if not sketch or sketch.investigation_id != investigation_id:
                raise NotFoundError("Sketch not found in this investigation")
        item = CaseItem(investigation_id=investigation_id, author_id=user_id, **values)
        self.db.add(item)
        self.db.flush()
        self.record(
            investigation_id,
            user_id,
            "created",
            item.id,
            {"kind": item.kind, "body": item.body},
        )
        self._commit()
        self._refresh(item)
        return item

    def update(
        self,
        investigation_id: UUID,
        item_id: UUID,
        user_id: UUID,
        version: int,
        values: dict[str, Any],
    ) -> CaseItem:
        self._check_permission(user_id, investigation_id, ["update"])
        item = (
            self.db.query(CaseItem)
            .filter_by(id=item_id, investigation_id=investigation_id)
            .first()
        )
        if not item:
            raise NotFoundError("Case item not found")
        if item.version != version:
            raise ConflictError(
                "This item changed. Reload before saving; your edits were not applied."
            )
        if "assignee_id" in values:
            self._validate_assignment(investigation_id, values["assignee_id"])
        if "decision" in values and values["decision"] != item.decision:
            self._check_permission(user_id, investigation_id, ["manage"])
            if values["decision"] != "pending" and (
                not values.get("assessment", item.assessment).strip()
                or not values.get("evidence", item.evidence).strip()
            ):
                raise ConflictError(
                    "Add supporting evidence and an assessment before review"
                )
            item.reviewer_id = user_id
        changes = {
            key: {
                "before": getattr(item, key),
                "after": str(value) if isinstance(value, UUID) else value,
            }
            for key, value in values.items()
            if getattr(item, key) != value
        }
        # Convert UUIDs in activity history to JSON values.
        for change in changes.values():
            if isinstance(change["before"], UUID):
                change["before"] = str(change["before"])
        for key, value in values.items():
            setattr(item, key, value)
        if (
            any(key in changes for key in ("body", "evidence", "assessment"))
            and "decision" not in changes
        ):
            item.decision = "pending"
            item.reviewer_id = None
            changes["review"] = {
                "after": "pending",
                "reason": "Finding or evidence changed",
            }
        item.updated_at = datetime.now(timezone.utc)
        self.record(investigation_id, user_id, "updated", item.id, changes)
        try:
            self.db.commit()
        except StaleDataError:
            self.db.rollback()
            raise ConflictError(
                "This item changed. Reload before saving; your edits were not applied."
            )
        except SQLAlchemyError as exc:
            self.db.rollback()
            raise DatabaseError(f"Database error: {exc}")
        self._refresh(item)
        return item
