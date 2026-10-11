"""Utilities for handling custom types: validation and dynamic model creation."""

import hashlib
import json
from typing import Any, Dict

from fastapi import HTTPException
from jsonschema import Draft7Validator
from jsonschema import ValidationError as JSONSchemaValidationError

# Whitelist of allowed JSON Schema types for security
ALLOWED_TYPES = {"string", "integer", "number", "boolean", "object", "array"}


def validate_json_schema(schema: Dict[str, Any]) -> None:
    """
    Validate that a schema is a valid JSON Schema.

    Args:
        schema: The JSON Schema to validate

    Raises:
        HTTPException: If the schema is invalid
    """
    try:
        Draft7Validator.check_schema(schema)
    except JSONSchemaValidationError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON Schema: {e.message}")

    # Additional security checks
    _check_schema_security(schema)


def _check_schema_security(schema: Dict[str, Any]) -> None:
    """
    Check schema for security issues.

    Args:
        schema: The JSON Schema to check

    Raises:
        HTTPException: If security issues are found
    """
    # Check if type is in whitelist
    schema_type = schema.get("type")
    if schema_type and schema_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Type '{schema_type}' is not allowed. Allowed types: {ALLOWED_TYPES}",
        )

    # Check properties recursively
    properties = schema.get("properties", {})
    for prop_name, prop_schema in properties.items():
        if isinstance(prop_schema, dict):
            prop_type = prop_schema.get("type")
            if prop_type and prop_type not in ALLOWED_TYPES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Type '{prop_type}' in property '{prop_name}' is not allowed",
                )


def validate_payload_against_schema(
    payload: Dict[str, Any], schema: Dict[str, Any]
) -> tuple[bool, list[str]]:
    """
    Validate a payload against a JSON Schema.

    Args:
        payload: The data to validate
        schema: The JSON Schema to validate against

    Returns:
        Tuple of (is_valid, error_messages)
    """
    validator = Draft7Validator(schema)
    errors = list(validator.iter_errors(payload))

    if errors:
        error_messages = [
            f"{'.'.join(str(p) for p in error.path)}: {error.message}"
            for error in errors
        ]
        return False, error_messages

    return True, []


def calculate_schema_checksum(schema: Dict[str, Any]) -> str:
    """
    Calculate a checksum for a schema to detect changes.

    Args:
        schema: The JSON Schema

    Returns:
        SHA256 checksum of the schema
    """
    schema_str = json.dumps(schema, sort_keys=True)
    return hashlib.sha256(schema_str.encode()).hexdigest()
