from typing import List, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.schemas.collaboration import (
    CaseActivityRead,
    CaseItemCreate,
    CaseItemRead,
    CaseItemUpdate,
)
from app.api.schemas.investigation import (
    CollaboratorAdd,
    CollaboratorRead,
    CollaboratorUpdate,
    InvestigationCreate,
    InvestigationRead,
    InvestigationUpdate,
)
from app.api.schemas.sketch import SketchRead
from flowsint_core.core.models import (
    CaseActivity,
    CaseItem,
    Investigation,
    Profile,
    Sketch,
)
from flowsint_core.core.postgre_db import get_db
from flowsint_core.core.services import (
    ConflictError,
    DatabaseError,
    NotFoundError,
    PermissionDeniedError,
    create_investigation_service,
)
from flowsint_core.core.services.collaboration_service import CollaborationService
from flowsint_core.core.services.investigation_service import InvestigationService
from flowsint_core.core.types import Role

router = APIRouter()


def _inject_current_user_role(
    service: InvestigationService, investigation: Investigation, user_id: UUID
) -> InvestigationRead:
    """Build InvestigationRead with the current user's role attached."""
    result = InvestigationRead.model_validate(investigation)
    role_entry = service.get_user_role_for_investigation(user_id, investigation.id)
    if role_entry and role_entry.roles:
        result.current_user_role = role_entry.roles[0].value
    return result


@router.get("", response_model=List[InvestigationRead])
def get_investigations(
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> List[InvestigationRead]:
    """Get all investigations accessible to the user based on their roles."""
    service = create_investigation_service(db)
    allowed_roles = [Role.OWNER, Role.ADMIN, Role.EDITOR, Role.VIEWER]
    investigations = service.get_accessible_investigations(
        user_id=current_user.id, allowed_roles=allowed_roles
    )
    return [
        _inject_current_user_role(service, inv, current_user.id)
        for inv in investigations
    ]


@router.post(
    "/create", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED
)
def create_investigation(
    payload: InvestigationCreate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> InvestigationRead:
    service = create_investigation_service(db)
    investigation = service.create(
        name=payload.name,
        description=payload.description,
        owner_id=current_user.id,
    )
    return _inject_current_user_role(service, investigation, current_user.id)


@router.get("/{investigation_id}", response_model=InvestigationRead)
def get_investigation_by_id(
    investigation_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> InvestigationRead:
    service = create_investigation_service(db)
    try:
        investigation = service.get_by_id(investigation_id, current_user.id)
        return _inject_current_user_role(service, investigation, current_user.id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.get("/{investigation_id}/sketches", response_model=List[SketchRead])
def get_sketches_by_investigation(
    investigation_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> List[Sketch]:
    service = create_investigation_service(db)
    try:
        return cast(
            List[Sketch], service.get_sketches(investigation_id, current_user.id)
        )
    except NotFoundError:
        raise HTTPException(
            status_code=404, detail="No sketches found for this investigation"
        )
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.put("/{investigation_id}", response_model=InvestigationRead)
def update_investigation(
    investigation_id: UUID,
    payload: InvestigationUpdate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> InvestigationRead:
    service = create_investigation_service(db)
    try:
        investigation = service.update(
            investigation_id=investigation_id,
            user_id=current_user.id,
            name=payload.name,
            description=payload.description,
            status=payload.status,
        )
        return _inject_current_user_role(service, investigation, current_user.id)
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(
    investigation_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> None:
    service = create_investigation_service(db)
    try:
        service.delete(investigation_id, current_user.id)
        return None
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Investigation not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")
    except DatabaseError:
        raise HTTPException(status_code=500, detail="Failed to clean up graph data")


# ── Collaborator endpoints ───────────────────────────────────────────


@router.get("/{investigation_id}/collaborators", response_model=List[CollaboratorRead])
def get_collaborators(
    investigation_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> List[CollaboratorRead]:
    service = create_investigation_service(db)
    try:
        entries = service.get_collaborators(investigation_id, current_user.id)
        return [
            CollaboratorRead(
                id=e.id,
                user_id=e.user_id,
                roles=[r.value for r in e.roles],
                user=e.user,
            )
            for e in entries
        ]
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.post(
    "/{investigation_id}/collaborators",
    response_model=CollaboratorRead,
    status_code=status.HTTP_201_CREATED,
)
def add_collaborator(
    investigation_id: UUID,
    payload: CollaboratorAdd,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> CollaboratorRead:
    service = create_investigation_service(db)
    try:
        role = Role(payload.role.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    try:
        entry = service.add_collaborator(
            investigation_id=investigation_id,
            user_id=current_user.id,
            target_email=payload.email,
            role=role,
        )
        return CollaboratorRead(
            id=entry.id,
            user_id=entry.user_id,
            roles=[r.value for r in entry.roles],
            user=entry.user,
        )
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e.message))
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")
    except ConflictError:
        raise HTTPException(status_code=409, detail="User is already a collaborator")


@router.put(
    "/{investigation_id}/collaborators/{user_id}",
    response_model=CollaboratorRead,
)
def update_collaborator_role(
    investigation_id: UUID,
    user_id: UUID,
    payload: CollaboratorUpdate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> CollaboratorRead:
    service = create_investigation_service(db)
    try:
        role = Role(payload.role.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid role")
    try:
        entry = service.update_collaborator_role(
            investigation_id=investigation_id,
            user_id=current_user.id,
            target_user_id=user_id,
            role=role,
        )
        return CollaboratorRead(
            id=entry.id,
            user_id=entry.user_id,
            roles=[r.value for r in entry.roles],
            user=entry.user,
        )
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Collaborator not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.delete(
    "/{investigation_id}/collaborators/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_collaborator(
    investigation_id: UUID,
    user_id: UUID,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> None:
    service = create_investigation_service(db)
    try:
        service.remove_collaborator(
            investigation_id=investigation_id,
            user_id=current_user.id,
            target_user_id=user_id,
        )
        return None
    except NotFoundError:
        raise HTTPException(status_code=404, detail="Collaborator not found")
    except PermissionDeniedError:
        raise HTTPException(status_code=403, detail="Forbidden")


# Case collaboration uses the same investigation roles as sketches and analyses.
@router.get("/{investigation_id}/items", response_model=list[CaseItemRead])
def get_case_items(
    investigation_id: UUID,
    offset: int = Query(default=0, ge=0),
    sketch_id: UUID | None = None,
    target_kind: str | None = None,
    target_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> list[CaseItem]:
    try:
        return cast(
            list[CaseItem],
            CollaborationService(db).items(
                investigation_id,
                current_user.id,
                offset,
                sketch_id,
                target_kind,
                target_id,
            ),
        )
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.message)


@router.get("/{investigation_id}/activity", response_model=list[CaseActivityRead])
def get_case_activity(
    investigation_id: UUID,
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> list[CaseActivity]:
    try:
        return cast(
            list[CaseActivity],
            CollaborationService(db).activity(
                investigation_id, current_user.id, offset
            ),
        )
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.message)


@router.post("/{investigation_id}/items", response_model=CaseItemRead, status_code=201)
def create_case_item(
    investigation_id: UUID,
    payload: CaseItemCreate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> CaseItem:
    try:
        return CollaborationService(db).create(
            investigation_id, current_user.id, payload.model_dump()
        )
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.message)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message)


@router.put("/{investigation_id}/items/{item_id}", response_model=CaseItemRead)
def update_case_item(
    investigation_id: UUID,
    item_id: UUID,
    payload: CaseItemUpdate,
    db: Session = Depends(get_db),
    current_user: Profile = Depends(get_current_user),
) -> CaseItem:
    try:
        return CollaborationService(db).update(
            investigation_id,
            item_id,
            current_user.id,
            payload.version,
            payload.model_dump(exclude_unset=True, exclude={"version"}),
        )
    except PermissionDeniedError as exc:
        raise HTTPException(status_code=403, detail=exc.message)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=exc.message)
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=exc.message)
