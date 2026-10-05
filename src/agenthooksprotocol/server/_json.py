"""Strict JSON parsing for public transports, independent of fixture runners."""

import json


def loads(data):
    def reject(_):
        raise ValueError("Non-JSON number")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    return json.loads(data, parse_constant=reject, object_pairs_hook=pairs)
