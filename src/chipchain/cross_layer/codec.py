"""Canonical JSON without clocks, runtime IDs, duplicate keys or non-finite numbers."""
import hashlib
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def serialize(model):
    checked = type(model).model_validate(model.model_dump())
    return canonical(checked.model_dump(mode='json'))


def sha256(model):
    return hashlib.sha256(serialize(model).encode()).hexdigest()


def parse(model_type, text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result

    def invalid(value):
        raise ValueError('Non-finite JSON number')

    return model_type.model_validate(json.loads(text, object_pairs_hook=unique, parse_constant=invalid))
