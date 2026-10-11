from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.schemas.analysis import AnalysisUpdate
from app.api.schemas.collaboration import CaseItemCreate, CaseItemUpdate


def test_graph_comments_require_complete_scoped_target():
    with pytest.raises(ValidationError):
        CaseItemCreate(
            kind="comment", body="Observation", target_kind="entity", target_id="123"
        )
    item = CaseItemCreate(
        kind="comment",
        body="Observation",
        sketch_id=uuid4(),
        target_kind="relationship",
        target_id="123",
    )
    assert item.target_id == "123"


def test_case_item_updates_require_version_and_reject_blank_or_null_text():
    with pytest.raises(ValidationError):
        CaseItemUpdate(body="Edit")
    for body in [" ", None]:
        with pytest.raises(ValidationError):
            CaseItemUpdate(version=1, body=body)
    assert CaseItemUpdate(version=1, assignee_id=None).model_dump(
        exclude_unset=True
    ) == {"version": 1, "assignee_id": None}


def test_analysis_updates_require_optimistic_version():
    with pytest.raises(ValidationError):
        AnalysisUpdate(content={"type": "doc"})
    assert AnalysisUpdate(version=2, title="Report").version == 2
