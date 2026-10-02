from typing import List, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.schemas.analysis import AnalysisCreate, AnalysisRead, AnalysisUpdate
from flowsint_core.core.models import Analysis, Profile
from flowsint_core.core.postgre_db import get_db
from flowsint_core.core.services import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    create_analysis_service,
)

router = APIRouter()


@router.get("", response_model=List[AnalysisRead])
def get_analyses(
    db: Session = Depends(get_db), current_user: Profile = Depends(get_current_user)
) -> List[Analysis]:
    """Get all analyses accessible to the current user."""
    service = create_analysis_service(db)
    return cast(List[Analysis], service.get_accessible_analyses(current_user.id))


@router.post(
    "/create", response_model=AnalysisRead, status_code=status.HTTP_201_CREATED
)
def create_analysis(
    payload: AnalysisCreate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> Analysis:
    service = create_analysis_service(db)
    try:
        return service.create(
            title=payload.title,
            description=payload.description,
            content=payload.content,
            investigation_id=payload.investigation_id,
            owner_id=current_user.id,
        )
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.get("/{analysis_id}", response_model=AnalysisRead)
def get_analysis_by_id(
    analysis_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> Analysis:
    service = create_analysis_service(db)
    try:
        return service.get_by_id(analysis_id, current_user.id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.get("/investigation/{investigation_id}", response_model=List[AnalysisRead])
def get_analyses_by_investigation(
    investigation_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> List[Analysis]:
    service = create_analysis_service(db)
    try:
        return cast(
            List[Analysis],
            service.get_by_investigation(investigation_id, current_user.id),
        )
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.put("/{analysis_id}", response_model=AnalysisRead)
def update_analysis(
    analysis_id: UUID,
    payload: AnalysisUpdate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> Analysis:
    service = create_analysis_service(db)
    try:
        return service.update(
            analysis_id=analysis_id,
            user_id=current_user.id,
            title=payload.title,
            description=payload.description,
            content=payload.content,
            investigation_id=payload.investigation_id,
            version=payload.version,
        )
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=exc.message)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> None:
    service = create_analysis_service(db)
    try:
        service.delete(analysis_id, current_user.id)
        return None
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")
