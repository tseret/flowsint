"""Test simplified API for create_node and create_relationship."""

from typing import Any, Dict, List, Optional

import pytest
from pydantic import BaseModel, Field

from flowsint_core.core.enricher_base import Enricher
from flowsint_types.domain import Domain
from flowsint_types.individual import Individual


class MockEnricher(Enricher):
    """Simple enricher for testing."""

    InputType = Domain
    OutputType = Domain

    @classmethod
    def name(cls) -> str:
        return "test_enricher"

    @classmethod
    def category(cls) -> str:
        return "Test"

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [{"name": "API_KEY", "type": "vaultSecret", "required": False}]

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        return data


def test_create_relationship_with_pydantic_objects():
    """Test that create_relationship works with Pydantic objects."""
    enricher = MockEnricher(sketch_id="test", scan_id="test")

    # Create objects
    individual = Individual(first_name="John", last_name="Doe", full_name="John Doe")
    domain = Domain(domain="example.com")

    # This should not raise an error
    enricher.create_relationship(individual, domain, "HAS_DOMAIN")


def test_create_node_with_property_override():
    """Test that property overrides work with Pydantic objects."""
    enricher = MockEnricher(sketch_id="test", scan_id="test")

    domain = Domain(domain="example.com")

    # Should be able to override properties
    enricher.create_node(domain)


class PrimaryFlagged(BaseModel):
    first: Optional[str] = None
    required_one: str
    flagged: Optional[str] = Field(None, json_schema_extra={"primary": True})


class RequiredOnly(BaseModel):
    first: Optional[str] = None
    required_one: str


class AllOptional(BaseModel):
    first: Optional[str] = None
    second: Optional[str] = None


@pytest.mark.parametrize(
    ("input_type", "expected"),
    [
        (Domain, "domain"),
        (PrimaryFlagged, "flagged"),
        (RequiredOnly, "required_one"),
        (AllOptional, "first"),
        (NotImplemented, None),
    ],
)
def test_default_key_is_input_type_primary_field(input_type, expected):
    enricher_cls = type("KeyedEnricher", (MockEnricher,), {"InputType": input_type})
    assert enricher_cls.key() == expected


def test_primary_field_drives_string_preprocess():
    enricher_cls = type("KeyedEnricher", (MockEnricher,), {"InputType": PrimaryFlagged})
    enricher = enricher_cls(sketch_id="test", scan_id="test")
    # A bare string lands in the primary field; required_one missing -> skipped.
    assert enricher.preprocess(["x", {"required_one": "r", "flagged": "f"}]) == [
        PrimaryFlagged(required_one="r", flagged="f")
    ]


def test_params_schema_defaults_to_declared_schema():
    enricher = MockEnricher(sketch_id="test", scan_id="test")
    assert enricher.params_schema == MockEnricher.get_params_schema()


def test_explicit_empty_params_schema_is_kept():
    enricher = MockEnricher(sketch_id="test", scan_id="test", params_schema=[])
    assert enricher.params_schema == []
