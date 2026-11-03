"""Loads the rule data (weights, brand list, phrase lists) from rules.json.

The same JSON file is bundled into the browser demo, so the Python tool and
the web page always score an email with identical data.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any


@lru_cache(maxsize=1)
def load_rules() -> dict[str, Any]:
    text = resources.files("phishcheck").joinpath("data/rules.json").read_text(encoding="utf-8")
    return json.loads(text)


def weight(rule_id: str) -> int:
    return int(load_rules()["weights"][rule_id])
