from uuid import uuid4

import pytest

from flowsint_core.core.models import (
    CaseActivity,
    CaseItem,
    Investigation,
    InvestigationUserRole,
    Profile,
    Sketch,
)
from flowsint_core.core.services.analysis_service import create_analysis_service
from flowsint_core.core.services.collaboration_service import CollaborationService
from flowsint_core.core.services.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
)
from flowsint_core.core.types import Role


def setup_case(db):
    users = [
        Profile(id=uuid4(), email=f"{n}@test.invalid", hashed_password="unused")
        for n in range(3)
    ]
    db.add_all(users)
    db.flush()
    inv = Investigation(id=uuid4(), name="Case", owner_id=users[0].id)
    db.add(inv)
    db.flush()
    for user, role in zip(users, [Role.OWNER, Role.EDITOR, Role.VIEWER]):
        db.add(
            InvestigationUserRole(
                id=uuid4(), user_id=user.id, investigation_id=inv.id, roles=[role]
            )
        )
    db.commit()
    return inv, users


def test_persistence_permissions_review_and_conflict(db_session):
    inv, (owner, editor, viewer) = setup_case(db_session)
    service = CollaborationService(db_session)
    with pytest.raises(PermissionDeniedError):
        service.create(inv.id, viewer.id, {"kind": "comment", "body": "no"})
    item = service.create(
        inv.id,
        editor.id,
        {"kind": "finding", "body": "Observation", "assignee_id": owner.id},
    )
    assert service.items(inv.id, viewer.id)[0].body == "Observation"
    assert service.activity(inv.id, viewer.id)[0].actor_name == editor.email
    version = item.version
    with pytest.raises(PermissionDeniedError):
        service.update(inv.id, item.id, editor.id, version, {"decision": "accepted"})
    with pytest.raises(ConflictError):
        service.update(inv.id, item.id, owner.id, version, {"decision": "accepted"})
    updated = service.update(
        inv.id,
        item.id,
        owner.id,
        version,
        {
            "evidence": "Provider observation",
            "assessment": "Supported",
            "decision": "accepted",
        },
    )
    assert updated.reviewer_id == owner.id
    assert updated.version == version + 1
    with pytest.raises(ConflictError):
        service.update(inv.id, item.id, editor.id, version, {"body": "stale overwrite"})
    assert db_session.get(CaseItem, item.id).body == "Observation"
    assert db_session.query(CaseActivity).count() == 2


def test_cross_case_targets_and_assignment_rejected(db_session):
    inv, users = setup_case(db_session)
    other, other_users = setup_case_second(db_session)
    sketch = Sketch(id=uuid4(), investigation_id=other.id, title="Other")
    db_session.add(sketch)
    db_session.commit()
    service = CollaborationService(db_session)
    with pytest.raises(NotFoundError):
        service.create(
            inv.id,
            users[0].id,
            {"kind": "comment", "body": "no", "sketch_id": sketch.id},
        )
    with pytest.raises(PermissionDeniedError):
        service.create(
            inv.id,
            users[0].id,
            {"kind": "question", "body": "no", "assignee_id": other_users[0].id},
        )
    with pytest.raises(PermissionDeniedError):
        service.items(inv.id, other_users[0].id)


def setup_case_second(db):
    user = Profile(id=uuid4(), email="other@test.invalid", hashed_password="unused")
    db.add(user)
    db.flush()
    inv = Investigation(id=uuid4(), name="Other", owner_id=user.id)
    db.add(inv)
    db.flush()
    db.add(
        InvestigationUserRole(
            id=uuid4(), user_id=user.id, investigation_id=inv.id, roles=[Role.OWNER]
        )
    )
    db.commit()
    return inv, [user]


def test_analysis_rejects_stale_edits(db_session):
    inv, users = setup_case(db_session)
    service = create_analysis_service(db_session)
    analysis = service.create("Report", None, None, inv.id, users[0].id)
    version = analysis.version
    service.update(analysis.id, users[0].id, title="Updated", version=version)
    with pytest.raises(ConflictError):
        service.update(analysis.id, users[1].id, title="Stale", version=version)
    assert analysis.title == "Updated"


def test_overlapping_sessions_cannot_overwrite_or_log_failed_save(db_session):
    from sqlalchemy.orm import Session

    inv, users = setup_case(db_session)
    service = CollaborationService(db_session)
    item = service.create(inv.id, users[0].id, {"kind": "comment", "body": "Initial"})
    item_id, inv_id, owner_id, version = item.id, inv.id, users[0].id, item.version
    with Session(db_session.bind, expire_on_commit=False) as other_db:
        stale = other_db.get(CaseItem, item_id)
        assert stale.version == version
        service.update(inv_id, item_id, owner_id, version, {"body": "First save"})
        with pytest.raises(ConflictError):
            CollaborationService(other_db).update(
                inv_id, item_id, owner_id, version, {"body": "Lost update"}
            )
    db_session.expire_all()
    assert db_session.get(CaseItem, item_id).body == "First save"
    assert db_session.query(CaseActivity).count() == 2


def test_editing_reviewed_evidence_requires_new_review(db_session):
    inv, users = setup_case(db_session)
    service = CollaborationService(db_session)
    item = service.create(inv.id, users[0].id, {"kind": "finding", "body": "Finding"})
    item = service.update(
        inv.id,
        item.id,
        users[0].id,
        item.version,
        {"evidence": "Original", "assessment": "Supported", "decision": "accepted"},
    )
    item = service.update(
        inv.id, item.id, users[1].id, item.version, {"evidence": "Changed"}
    )
    assert item.decision == "pending"
    assert item.reviewer_id is None


def test_investigation_and_collaborator_changes_record_actor(db_session):
    from flowsint_core.core.services.investigation_service import (
        create_investigation_service,
    )

    inv, users = setup_case(db_session)
    newcomer = Profile(id=uuid4(), email="new@test.invalid", hashed_password="unused")
    db_session.add(newcomer)
    db_session.commit()
    service = create_investigation_service(db_session)
    service.update(inv.id, users[0].id, "Updated case", "Description", "active")
    service.add_collaborator(inv.id, users[0].id, newcomer.email, Role.VIEWER)
    service.update_collaborator_role(inv.id, users[0].id, newcomer.id, Role.EDITOR)
    service.remove_collaborator(inv.id, users[0].id, newcomer.id)
    activity = CollaborationService(db_session).activity(inv.id, users[1].id)
    assert {event.action for event in activity} == {
        "investigation updated",
        "collaborator added",
        "collaborator role updated",
        "collaborator removed",
    }
    assert all(event.actor_id == users[0].id for event in activity)
