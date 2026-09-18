"""End-to-end tests for POST /audit/licenses."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _audit(**payload):
    response = client.post("/audit/licenses", json=payload)
    return response.status_code, response.json()


def test_health_still_ok():
    response = client.get("/health")
    assert response.status_code == 200


def test_basic_classification_and_missing():
    status, body = _audit(
        resolved={"ok": "1.0", "bad": "2.0", "mystery": "1.1", "unlicensed": "0.1"},
        licenses={
            "ok": "MIT",
            "bad": "GPL-3.0-only",
            "mystery": "Beerware",
            # "unlicensed" has no expression -> missing
        },
        allowed=["MIT"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {
        "packages": 4,
        "compliant": 1,
        "violation": 1,
        "unknown": 1,
        "missing": 1,
    }

    (ok,) = body["compliant"]
    assert ok == {
        "package": "ok",
        "version": "1.0",
        "expression": "MIT",
        "status": "compliant",
        "deciding_identifiers": ["MIT"],
    }
    (bad,) = body["violation"]
    assert bad["package"] == "bad"
    assert bad["deciding_identifiers"] == ["GPL-3.0-only"]
    (mystery,) = body["unknown"]
    assert mystery["package"] == "mystery"
    assert mystery["deciding_identifiers"] == ["Beerware"]
    (unlicensed,) = body["missing"]
    assert unlicensed == {
        "package": "unlicensed",
        "version": "0.1",
        "expression": None,
        "status": "missing",
        "deciding_identifiers": [],
    }


def test_and_semantics():
    # any violation -> violation
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT AND GPL-3.0-only AND Apache-2.0"},
        allowed=["MIT", "Apache-2.0"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    (entry,) = body["violation"]
    assert entry["deciding_identifiers"] == ["GPL-3.0-only"]

    # no violation but an unknown -> unknown
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT AND Beerware"},
        allowed=["MIT"],
    )
    assert status == 200
    (entry,) = body["unknown"]
    assert entry["deciding_identifiers"] == ["Beerware"]

    # all allowed -> compliant, every identifier decides
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT AND Apache-2.0"},
        allowed=["MIT", "Apache-2.0"],
    )
    assert status == 200
    (entry,) = body["compliant"]
    assert entry["deciding_identifiers"] == ["Apache-2.0", "MIT"]


def test_or_semantics():
    # any compliant -> compliant
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "GPL-3.0-only OR MIT"},
        allowed=["MIT"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    (entry,) = body["compliant"]
    assert entry["deciding_identifiers"] == ["MIT"]

    # no compliant but an unknown -> unknown
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "GPL-3.0-only OR Beerware"},
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    (entry,) = body["unknown"]
    assert entry["deciding_identifiers"] == ["Beerware"]

    # all denied -> violation, every identifier decides
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "GPL-2.0-only OR GPL-3.0-only"},
        denied=["GPL-2.0-only", "GPL-3.0-only"],
    )
    assert status == 200
    (entry,) = body["violation"]
    assert entry["deciding_identifiers"] == ["GPL-2.0-only", "GPL-3.0-only"]


def test_with_is_judged_like_and():
    # license allowed but exception denied -> violation
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "Apache-2.0 WITH LLVM-exception"},
        allowed=["Apache-2.0"],
        denied=["LLVM-exception"],
    )
    assert status == 200
    (entry,) = body["violation"]
    assert entry["expression"] == "Apache-2.0 WITH LLVM-exception"
    assert entry["deciding_identifiers"] == ["LLVM-exception"]

    # both allowed -> compliant
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "Apache-2.0 WITH LLVM-exception"},
        allowed=["Apache-2.0", "LLVM-exception"],
    )
    assert status == 200
    (entry,) = body["compliant"]
    assert entry["deciding_identifiers"] == ["Apache-2.0", "LLVM-exception"]

    # license allowed, exception unknown -> unknown
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "Apache-2.0 WITH LLVM-exception"},
        allowed=["Apache-2.0"],
    )
    assert status == 200
    (entry,) = body["unknown"]
    assert entry["deciding_identifiers"] == ["LLVM-exception"]


def test_parentheses_and_nested_expressions():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT AND (GPL-2.0-only OR (Apache-2.0 AND BSD-3-Clause))"},
        allowed=["MIT", "Apache-2.0", "BSD-3-Clause"],
        denied=["GPL-2.0-only"],
    )
    assert status == 200
    (entry,) = body["compliant"]
    assert entry["expression"] == (
        "MIT AND (GPL-2.0-only OR (Apache-2.0 AND BSD-3-Clause))"
    )
    # The denied GPL branch loses the OR to the compliant Apache+BSD branch.
    assert entry["deciding_identifiers"] == ["Apache-2.0", "BSD-3-Clause", "MIT"]


def test_expression_and_policy_identifiers_are_normalized():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "mit and (apache-2.0 or gpl-2.0-only)"},
        allowed=["mIt", "APACHE-2.0"],
    )
    assert status == 200
    (entry,) = body["compliant"]
    # Known SPDX keys are canonicalized in the reported expression.
    assert entry["expression"] == "MIT AND (Apache-2.0 OR GPL-2.0-only)"
    # Case-insensitive policy match: the OR branch is compliant via Apache-2.0.
    assert entry["deciding_identifiers"] == ["Apache-2.0", "MIT"]


def test_denied_wins_over_allowed():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT"},
        allowed=["MIT"],
        denied=["MIT"],
    )
    assert status == 200
    assert body["summary"]["violation"] == 1


def test_packages_sorted_by_normalized_name():
    status, body = _audit(
        resolved={"Zeta": "1.0", "Alpha_Lib": "2.0", "mid": "1.0"},
        licenses={"Zeta": "MIT", "Alpha_Lib": "MIT", "mid": "GPL-3.0-only"},
        allowed=["MIT"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    # Names are canonicalized (PEP 503) and each status list is sorted.
    assert [e["package"] for e in body["compliant"]] == ["alpha-lib", "zeta"]
    assert [e["package"] for e in body["violation"]] == ["mid"]


def test_empty_policy_marks_everything_unknown():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT"},
    )
    assert status == 200
    assert body["summary"] == {
        "packages": 1,
        "compliant": 0,
        "violation": 0,
        "unknown": 1,
        "missing": 0,
    }


def test_roundtrip_from_resolve_response():
    resolve_body = client.post(
        "/resolve",
        json={
            "packages": {
                "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
                "web": {"2.0": {}},
                "db": {"1.0": {}},
            },
            "root": {"app": ""},
        },
    ).json()
    assert resolve_body["status"] == "ok"

    status, body = _audit(
        resolved=resolve_body["resolved"],
        licenses={"app": "MIT", "web": "Apache-2.0", "db": "GPL-3.0-only"},
        allowed=["MIT", "Apache-2.0"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    assert body["summary"] == {
        "packages": 3,
        "compliant": 2,
        "violation": 1,
        "unknown": 0,
        "missing": 0,
    }
    assert [e["package"] for e in body["compliant"]] == ["app", "web"]
    assert [e["package"] for e in body["violation"]] == ["db"]


def test_deterministic_results():
    payload = {
        "resolved": {"a": "1.0", "b": "1.0", "c": "1.0"},
        "licenses": {
            "a": "MIT AND (Apache-2.0 OR GPL-2.0-only)",
            "b": "Apache-2.0 WITH LLVM-exception",
            "c": "Beerware",
        },
        "allowed": ["MIT", "Apache-2.0"],
        "denied": ["GPL-2.0-only"],
    }
    results = [client.post("/audit/licenses", json=payload).json() for _ in range(5)]
    assert all(r == results[0] for r in results)


# ---------------------------------------------------------------------------
# 400s
# ---------------------------------------------------------------------------


def test_invalid_expression_returns_400_without_partial_results():
    status, body = _audit(
        resolved={"good": "1.0", "bad": "1.0"},
        licenses={"good": "MIT", "bad": "MIT AND"},
        allowed=["MIT"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    # No per-package results leak out of a failed request.
    assert "compliant" not in body
    assert "summary" not in body


def test_unbalanced_parentheses_return_400():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "(MIT OR Apache-2.0"},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_empty_expression_returns_400():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "   "},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_invalid_expression_for_unresolved_package_still_returns_400():
    # Expressions are validated up front, even for packages not in resolved.
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT", "ghost": "AND OR"},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_expression_in_policy_returns_400():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT"},
        allowed=["MIT OR Apache-2.0"],
    )
    assert status == 400
    assert "single license identifier" in body["error"]["message"]


def test_invalid_policy_identifier_returns_400():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"p": "MIT"},
        denied=["MIT AND"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_invalid_resolved_version_returns_400():
    status, body = _audit(
        resolved={"p": "not-a-version"},
        licenses={"p": "MIT"},
    )
    assert status == 400
    assert "PEP 440" in body["error"]["message"]


def test_duplicate_package_after_normalization_returns_400():
    status, body = _audit(
        resolved={"alpha-lib": "1.0"},
        licenses={"Alpha_Lib": "MIT", "alpha-lib": "Apache-2.0"},
    )
    assert status == 400
    assert "duplicates" in body["error"]["message"]


def test_root_name_reserved_returns_400():
    status, body = _audit(
        resolved={"p": "1.0"},
        licenses={"<root>": "MIT"},
    )
    assert status == 400
    assert "reserved" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/audit/licenses",
        json={"resolved": {}, "licenses": {}, "nope": 1},
    )
    assert response.status_code == 422
