import hashlib
import uuid
from datetime import timezone

from dacite import from_dict
from dateutil import parser as datetimeparser

from cscapi.storage import SignalModel, SourceModel


def generate_machine_id_from_key(key, prefix: str = "", length=48) -> str:
    """Generate a deterministic machine id based on the input key and prefix"""
    # Concatenate key and prefix
    input_str = f"{prefix}{key}"

    # Use a hash function (SHA-256 in this case)
    hash_object = hashlib.sha256(input_str.encode())

    # Take the first `length` characters of the hexadecimal digest
    hashed_str = hash_object.hexdigest()[:length]

    # Combine the hashed string and the prefix
    machine_id = f"{prefix}{hashed_str}"

    return machine_id


def create_signal(
    attacker_ip: str, scenario: str, created_at: str, machine_id: str, **kwargs
) -> SignalModel:
    created_at = (
        datetimeparser.parse(created_at)
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S%z")
    )

    if "start_at" not in kwargs:
        kwargs["start_at"] = created_at

    if "stop_at" not in kwargs:
        kwargs["stop_at"] = created_at

    if "scenario_trust" not in kwargs:
        kwargs["scenario_trust"] = "manual"

    if "uuid" not in kwargs:
        kwargs["uuid"] = str(uuid.uuid4())

    kwargs["source"] = {"value": attacker_ip, "scope": "ip"}
    kwargs["scenario"] = scenario
    kwargs["created_at"] = created_at
    kwargs["machine_id"] = machine_id

    return from_dict(SignalModel, kwargs)
