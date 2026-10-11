from unittest.mock import MagicMock

import pytest

from flowsint_core.core.graph import Neo4jGraphRepository


def test_slice_bounds_nodes_and_dense_edges_and_reports_full_counts():
    connection = MagicMock()
    connection.query.side_effect = [
        [{"total_nodes": 9000}],
        [{"total_edges": 30000}],
        [{"id": str(i)} for i in range(4)],
        [{"id": str(i)} for i in range(10001)],
    ]
    repo = Neo4jGraphRepository(connection)
    result = repo.get_graph_slice("case-a", ["seed"], "EXAMPLE", limit=3)
    assert len(result["nodes"]) == 3
    assert len(result["edges"]) == 10000
    assert result["total_nodes"] == 9000
    assert result["total_edges"] == 30000
    assert result["truncated"] is True
    query, params = connection.query.call_args_list[2].args
    assert params["sketch_id"] == "case-a"
    assert params["search"] == "example"
    assert params["limit"] == 4
    assert "c.sketch_id = $sketch_id" in query
    assert "r.deleted_at IS NULL" in query
    assert connection.query.call_args_list[3].args[1]["ids"] == ["0", "1", "2"]


def test_small_complete_graph_is_not_marked_partial():
    connection = MagicMock()
    connection.query.side_effect = [
        [{"total_nodes": 1}],
        [{"total_edges": 0}],
        [{"id": "a"}],
        [],
    ]
    result = Neo4jGraphRepository(connection).get_graph_slice("case-a")
    assert result["truncated"] is False


@pytest.mark.parametrize(
    "limit,offset,centers",
    [(0, 0, []), (2001, 0, []), (1, -1, []), (1, 0, ["x"] * 101)],
)
def test_invalid_bounds_never_query(limit, offset, centers):
    connection = MagicMock()
    with pytest.raises(ValueError):
        Neo4jGraphRepository(connection).get_graph_slice(
            "case", centers, limit=limit, offset=offset
        )
    connection.query.assert_not_called()


def test_full_graph_reports_truncation_instead_of_silent_loss():
    connection = MagicMock()
    connection.query.side_effect = [[{"id": "a"}, {"id": "b"}], []]
    result = Neo4jGraphRepository(connection).get_sketch_graph("case", limit=1)
    assert result["nodes"] == [{"id": "a"}]
    assert result["truncated"] is True
