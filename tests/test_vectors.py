"""TV-L--01..60: the sixty numbered conformance vectors (spec §15.3).

Each test loads its vector from tests/vectors.json, substitutes the named
fixtures, executes the real op, and asserts deep equality with the declared
expected output.
"""

import json
import os

import pytest

from fixtures import substitute
from harness import run_op

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "vectors.json")

with open(VECTORS_PATH, "rb") as f:
    VECTORS = json.load(f)["vectors"]

assert len(VECTORS) == 60, "the suite must contain exactly 60 vectors"


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vector, tmp_path):
    inp = substitute(vector["input"])
    expected = substitute(vector["expected"])
    got = run_op(inp, str(tmp_path))
    assert got == expected, (
        f"{vector['id']} {vector['name']}\ninput:    {json.dumps(inp)}\n"
        f"expected: {json.dumps(expected)}\ngot:      {json.dumps(got)}"
    )
