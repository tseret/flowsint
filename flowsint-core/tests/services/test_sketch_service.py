from unittest.mock import MagicMock, patch
from uuid import uuid4

from flowsint_core.core.graph import GraphNode, NodeMetadata
from flowsint_core.core.services.sketch_service import SketchService


def test_add_node_returns_persisted_version_for_immediate_editing():
    service = SketchService(MagicMock(), MagicMock(), MagicMock())
    service._get_sketch_with_permission = MagicMock()
    submitted = GraphNode(
        id=None,
        nodeLabel="example.com",
        nodeType="domain",
        nodeProperties={"domain": "example.com"},
        nodeMetadata=NodeMetadata(),
    )
    stored = submitted.model_copy(update={"id": "element-1", "version": 7})
    with patch(
        "flowsint_core.core.services.sketch_service.create_graph_service"
    ) as factory:
        factory.return_value.create_node.return_value = stored.id
        factory.return_value.get_nodes_by_ids.return_value = [stored]
        result = service.add_node(uuid4(), uuid4(), submitted)
    assert result["node"].version == 7
    assert result["node"].id == "element-1"
