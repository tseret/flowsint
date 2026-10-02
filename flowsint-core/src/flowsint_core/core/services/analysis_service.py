"""
Analysis service for managing analyses within investigations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import StaleDataError

from ..models import Analysis
from ..repositories import AnalysisRepository, InvestigationRepository
from .base import BaseService
from .collaboration_service import CollaborationService
from .exceptions import ConflictError, DatabaseError, NotFoundError


class AnalysisService(BaseService):
    """
    Service for analysis CRUD operations.
    """

    def __init__(
        self,
        db: Session,
        analysis_repo: AnalysisRepository,
        investigation_repo: InvestigationRepository,
        **kwargs: Any,
    ) -> None:
        super().__init__(db, **kwargs)
        self._analysis_repo = analysis_repo
        self._investigation_repo = investigation_repo

    def get_accessible_analyses(self, user_id: UUID) -> List[Analysis]:
        return self._analysis_repo.get_accessible_by_user(user_id)

    def get_by_id(self, analysis_id: UUID, user_id: UUID) -> Analysis:
        analysis = self._analysis_repo.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundError("Analysis not found")

        self._check_permission(user_id, analysis.investigation_id, ["read"])
        return analysis

    def get_by_investigation(
        self, investigation_id: UUID, user_id: UUID
    ) -> List[Analysis]:
        self._check_permission(user_id, investigation_id, ["read"])
        return self._analysis_repo.get_by_investigation(investigation_id)

    def create(
        self,
        title: str,
        description: Optional[str],
        content: Optional[Dict[str, Any]],
        investigation_id: UUID,
        owner_id: UUID,
    ) -> Analysis:
        self._check_permission(owner_id, investigation_id, ["create"])

        new_analysis = Analysis(
            id=uuid4(),
            title=title,
            description=description,
            content=content,
            owner_id=owner_id,
            investigation_id=investigation_id,
            created_at=datetime.now(timezone.utc),
            last_updated_at=datetime.now(timezone.utc),
        )
        self._analysis_repo.add(new_analysis)
        CollaborationService(self.db).record(
            investigation_id,
            owner_id,
            "analysis created",
            new_analysis.id,
            {"title": title},
        )
        self._commit()
        self._refresh(new_analysis)
        return new_analysis

    def update(
        self,
        analysis_id: UUID,
        user_id: UUID,
        title: Optional[str] = None,
        description: Optional[str] = None,
        content: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[UUID] = None,
        version: Optional[int] = None,
    ) -> Analysis:
        analysis = self._analysis_repo.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundError("Analysis not found")

        self._check_permission(user_id, analysis.investigation_id, ["update"])
        if version is None or analysis.version != version:
            raise ConflictError(
                "This analysis changed. Reload before saving; your edits were not applied."
            )

        if title is not None:
            analysis.title = title
        if description is not None:
            analysis.description = description
        if content is not None:
            analysis.content = content
        if investigation_id is not None:
            self._check_permission(user_id, investigation_id, ["update"])
            analysis.investigation_id = investigation_id

        analysis.last_updated_at = datetime.now(timezone.utc)
        CollaborationService(self.db).record(
            analysis.investigation_id,
            user_id,
            "analysis updated",
            analysis.id,
            {"title": analysis.title},
        )
        try:
            self.db.commit()
        except StaleDataError:
            self.db.rollback()
            raise ConflictError(
                "This analysis changed. Reload before saving; your edits were not applied."
            )
        except SQLAlchemyError as exc:
            self.db.rollback()
            raise DatabaseError(f"Database error: {exc}")
        self._refresh(analysis)
        return analysis

    def delete(self, analysis_id: UUID, user_id: UUID) -> None:
        analysis = self._analysis_repo.get_by_id(analysis_id)
        if not analysis:
            raise NotFoundError("Analysis not found")

        self._check_permission(user_id, analysis.investigation_id, ["delete"])

        self._analysis_repo.delete(analysis)
        CollaborationService(self.db).record(
            analysis.investigation_id,
            user_id,
            "analysis deleted",
            analysis.id,
            {"title": analysis.title},
        )
        self._commit()


def create_analysis_service(db: Session) -> AnalysisService:
    investigation_repo = InvestigationRepository(db)
    return AnalysisService(
        db=db,
        analysis_repo=AnalysisRepository(db),
        investigation_repo=investigation_repo,
    )
