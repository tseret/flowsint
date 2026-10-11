from flowsint_core.core.services.evidence_correlations import summarize_evidence


def record(id, subject="host", provider="one", time="2026-01-01T00:00:00Z", **facts):
    return {
        "id": id,
        "node_ids": ["source", subject],
        "data": {"provider": provider, "observed_at": time, "facts": facts},
    }


def test_shared_fingerprints_cite_distinct_subjects_and_keep_zero():
    result = summarize_evidence(
        {
            "observations": [
                record("a", "host-a", fingerprints={"banner_hash": 0}),
                record("b", "host-b", fingerprints={"banner_hash": 0}),
                record("c", "host-a", fingerprints={"tls_sha256": "unique"}),
            ]
        }
    )
    assert result["shared_fingerprints"] == [
        {
            "fingerprint": "banner_hash",
            "value": "0",
            "subject_ids": ["host-a", "host-b"],
            "observation_ids": ["a", "b"],
        }
    ]


def test_only_exact_timestamp_different_provider_conflicts_and_same_provider_changes():
    result = summarize_evidence(
        {
            "observations": [
                record("a", service="http"),
                record(
                    "b", provider="two", time="2026-01-01T01:00:00+01:00", service="ssh"
                ),
                record("c", time="2026-01-02T00:00:00Z", service="https"),
                record("d", provider="two", time="2026-01-03", service="smtp"),
            ]
        }
    )
    assert len(result["contemporaneous_conflicts"]) == 1
    assert {
        a["observation_id"]
        for a in result["contemporaneous_conflicts"][0]["assertions"]
    } == {"a", "b"}
    assert len(result["recorded_changes"]) == 1
    assert result["recorded_changes"][0]["observation_ids"] == ["a", "c"]


def test_legacy_properties_missing_facts_and_different_subjects_are_not_conflicts():
    result = summarize_evidence(
        {
            "entities": [{"properties": {"service": "ssh"}}],
            "observations": [
                {"id": "legacy", "node_ids": ["host"], "data": {"provider": "one"}},
                record("a", "host-a", service="http"),
                record("b", "host-b", service="ssh"),
                record("c", time="invalid", service="ssh"),
            ],
        }
    )
    assert not result["shared_fingerprints"]
    assert not result["contemporaneous_conflicts"]
    assert not result["recorded_changes"]


def test_caps_and_input_not_mutated():
    data = {
        "observations": [
            record(str(i), str(i), fingerprints={"hash": "shared"}) for i in range(101)
        ]
    }
    result = summarize_evidence(data)
    assert result["truncated"]
    assert len(result["shared_fingerprints"][0]["subject_ids"]) == 100
    assert len(data["observations"]) == 101


def test_ambiguous_same_provider_instant_does_not_choose_arbitrary_change_or_conflict():
    result = summarize_evidence(
        {
            "observations": [
                record("a", service="http"),
                record("b", service="ssh"),
                record("c", time="2026-01-02T00:00:00Z", service="smtp"),
                record("d", provider="two", service="http"),
            ]
        }
    )
    assert not result["recorded_changes"]
    assert not result["contemporaneous_conflicts"]
