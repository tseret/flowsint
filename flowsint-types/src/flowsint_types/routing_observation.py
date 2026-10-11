from typing import Optional, Self

from pydantic import Field, model_validator

from .flowsint_base import FlowsintType
from .registry import flowsint_type


@flowsint_type
class RoutingObservation(FlowsintType):
    """A historical BGP announcement interval observed by RIPE RIS collectors."""

    reference: str = Field(
        ...,
        json_schema_extra={"primary": True},
        description="Prefix, origin ASN and observation interval",
    )
    prefix: str
    origin_asn: str
    start_time: str
    end_time: str
    visibility: Optional[float] = None
    source: str

    @model_validator(mode="after")
    def compute_label(self) -> Self:
        self.nodeLabel = self.reference
        return self
