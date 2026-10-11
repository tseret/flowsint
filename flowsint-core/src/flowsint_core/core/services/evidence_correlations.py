"""Bounded comparisons of recorded facts; no provider calls or ownership inference."""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def summarize_evidence(observation: dict[str, Any]) -> dict[str, Any]:
    """Compare explicit fact snapshots, never mutable entity properties or absence."""
    records = observation.get("observations", [])
    records = records if isinstance(records, list) else []
    fingerprints: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    comparable: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    truncated = bool(observation.get("truncated")) or len(records) > 100
    for record in records[:100]:
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            continue
        data = record.get("data")
        nodes = record.get("node_ids")
        if not isinstance(data, dict) or not isinstance(nodes, list) or not nodes:
            continue
        facts = data.get("facts")
        if not isinstance(facts, dict):
            continue
        subject = str(data.get("subject_id") or nodes[-1])
        entry = {
            "observation_id": record["id"],
            "subject_id": subject,
            "provider": str(data.get("provider") or ""),
            "time": _timestamp(data.get("observed_at")),
        }
        raw_fingerprints = facts.get("fingerprints")
        if isinstance(raw_fingerprints, dict):
            truncated |= len(raw_fingerprints) > 20
            for key, value in list(raw_fingerprints.items())[:20]:
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    value = str(value)
                    if value and len(value) <= 512 and len(key) <= 100:
                        fingerprints[(key, value)].append(entry)
        # These are single-valued assertions; collections and banners aren't comparable.
        for field in ("service", "version", "status", "issuer", "subject"):
            value = facts.get(field)
            if (
                isinstance(value, (str, int, bool))
                and value != ""
                and len(str(value)) <= 512
                and entry["time"] is not None
                and entry["provider"]
            ):
                comparable[(subject, field)].append({**entry, "value": value})

    shared = []
    for (field, value), entries in sorted(fingerprints.items()):
        subjects = sorted({entry["subject_id"] for entry in entries})
        if len(subjects) > 1:
            shared.append(
                {
                    "fingerprint": field,
                    "value": value,
                    "subject_ids": subjects,
                    "observation_ids": sorted({e["observation_id"] for e in entries}),
                }
            )

    conflicts = []
    changes = []
    for (subject, field), entries in sorted(comparable.items()):
        by_time: dict[datetime, list[dict[str, Any]]] = defaultdict(list)
        by_provider: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in entries:
            by_time[entry["time"]].append(entry)
            by_provider[entry["provider"]].append(entry)
        for timestamp, simultaneous in sorted(by_time.items()):
            provider_values: dict[str, set[tuple[str, str]]] = defaultdict(set)
            for entry in simultaneous:
                provider_values[entry["provider"]].add(
                    (type(entry["value"]).__name__, str(entry["value"]))
                )
            simultaneous = [
                e for e in simultaneous if len(provider_values[e["provider"]]) == 1
            ]
            values = {
                (type(e["value"]).__name__, str(e["value"])) for e in simultaneous
            }
            providers = {e["provider"] for e in simultaneous}
            if len(values) > 1 and len(providers) > 1:
                conflicts.append(
                    {
                        "subject_id": subject,
                        "field": field,
                        "observed_at": timestamp.isoformat(),
                        "assertions": [
                            {k: e[k] for k in ("provider", "value", "observation_id")}
                            for e in sorted(
                                simultaneous, key=lambda e: e["observation_id"]
                            )
                        ],
                    }
                )
        for provider, history in sorted(by_provider.items()):
            # Conflicting snapshots at one instant cannot establish an ordered change.
            if any(
                len(
                    {
                        (type(e["value"]).__name__, str(e["value"]))
                        for e in same_time
                        if e["provider"] == provider
                    }
                )
                > 1
                for same_time in by_time.values()
            ):
                continue
            ordered = sorted(history, key=lambda e: (e["time"], e["observation_id"]))
            for before, after in zip(ordered, ordered[1:]):
                if before["time"] < after["time"] and before["value"] != after["value"]:
                    changes.append(
                        {
                            "subject_id": subject,
                            "field": field,
                            "provider": provider,
                            "before": before["value"],
                            "after": after["value"],
                            "before_observed_at": before["time"].isoformat(),
                            "after_observed_at": after["time"].isoformat(),
                            "observation_ids": [
                                before["observation_id"],
                                after["observation_id"],
                            ],
                        }
                    )
    return {
        "shared_fingerprints": shared[:20],
        "contemporaneous_conflicts": conflicts[:20],
        "recorded_changes": changes[:20],
        "truncated": truncated
        or any(len(items) > 20 for items in (shared, conflicts, changes)),
        "scope": "Explicit recorded facts only. Shared fingerprints do not establish common control; changes do not establish absence between observations.",
    }
