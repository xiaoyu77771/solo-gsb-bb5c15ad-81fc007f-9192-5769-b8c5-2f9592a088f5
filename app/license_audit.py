"""License policy audit over a resolved dependency set.

Consumes the ``resolved`` mapping emitted by a successful ``/resolve`` call
together with a package -> SPDX license expression mapping and a local
allow/deny policy, and classifies every resolved package as ``compliant``,
``violation``, ``unknown`` or ``missing`` (no expression supplied).

Expressions are parsed with the ``license-expression`` library (the SPDX
parser that also powers ScanCode), so parentheses, ``AND``, ``OR`` and
``WITH`` all follow SPDX semantics and known identifiers are canonicalized
(``mit`` -> ``MIT``).  ``WITH`` is evaluated like ``AND``: the license and
the exception are classified independently and combined with AND rules.

Leaf classification: an identifier listed in ``denied`` is a violation, one
listed in ``allowed`` is compliant (denied wins when an identifier appears in
both), anything else is unknown.  Combination rules:

* ``AND`` / ``WITH``: any violation -> violation; otherwise any unknown ->
  unknown; otherwise compliant.
* ``OR``: any compliant -> compliant; otherwise any unknown -> unknown;
  otherwise violation.

The ``deciding_identifiers`` of a package are the leaf identifiers whose own
classification equals the package's final status -- exactly the identifiers
that drove the outcome.

Every expression and policy identifier is validated up front: any invalid
input raises ``ResolutionInputError`` (HTTP 400) before a single package is
classified, so a malformed request never yields partial results.
"""

from __future__ import annotations

from typing import Any, Iterable

from boolean import AND, OR
from license_expression import (
    ExpressionError,
    LicenseSymbol,
    LicenseWithExceptionSymbol,
    get_spdx_licensing,
)
from packaging.utils import canonicalize_name

from .audit import parse_resolved
from .resolver import ROOT, ResolutionInputError

STATUS_COMPLIANT = "compliant"
STATUS_VIOLATION = "violation"
STATUS_UNKNOWN = "unknown"
STATUS_MISSING = "missing"

# SPDX-aware parser: knows every SPDX license/exception key and canonicalizes
# them case-insensitively; unknown identifiers still parse as plain symbols.
_LICENSING = get_spdx_licensing()


# ---------------------------------------------------------------------------
# Input validation (all failures -> ResolutionInputError -> HTTP 400)
# ---------------------------------------------------------------------------


def parse_expression(text: str, origin: str) -> Any:
    """Parse one SPDX expression; empty or malformed text is a 400."""
    if not isinstance(text, str) or not text.strip():
        raise ResolutionInputError(
            f"{origin}: license expression must be a non-empty string"
        )
    try:
        parsed = _LICENSING.parse(text)
    except ExpressionError as exc:
        raise ResolutionInputError(
            f"{origin}: invalid SPDX expression {text!r}: {exc}"
        )
    if parsed is None:  # the library maps blank input to None instead of raising
        raise ResolutionInputError(
            f"{origin}: invalid SPDX expression {text!r}"
        )
    return parsed


def parse_licenses(raw: dict[str, str]) -> dict[str, Any]:
    """Validate the package -> SPDX expression mapping.

    Keys are canonicalized like package names everywhere else in the service
    and every expression is parsed up front, so an invalid expression fails
    the whole request instead of producing partial results.
    """
    expressions: dict[str, Any] = {}
    for package, text in raw.items():
        canonical = canonicalize_name(package)
        if canonical == ROOT:
            raise ResolutionInputError(
                f"licenses: {ROOT!r} is reserved and cannot name a package"
            )
        if canonical in expressions:
            raise ResolutionInputError(
                f"licenses: package {package!r} duplicates {canonical!r} "
                "after name normalization"
            )
        expressions[canonical] = parse_expression(text, f"licenses[{package!r}]")
    return expressions


def parse_policy_identifiers(raw: Iterable[str], origin: str) -> set[str]:
    """Normalize policy identifiers to their canonical SPDX rendering.

    Each entry must be a single license or exception identifier, not an
    expression.  Known SPDX keys are canonicalized case-insensitively, so
    ``mit`` in the policy matches ``MIT`` in an expression; unknown
    identifiers are matched verbatim.
    """
    identifiers: set[str] = set()
    for entry in raw:
        parsed = parse_expression(entry, origin)
        if not isinstance(parsed, LicenseSymbol):
            raise ResolutionInputError(
                f"{origin}: {entry!r} must be a single license identifier, "
                "not an expression"
            )
        identifiers.add(str(parsed))
    return identifiers


# ---------------------------------------------------------------------------
# Expression evaluation
# ---------------------------------------------------------------------------


def _classify_leaf(identifier: str, allowed: set[str], denied: set[str]) -> str:
    if identifier in denied:
        return STATUS_VIOLATION
    if identifier in allowed:
        return STATUS_COMPLIANT
    return STATUS_UNKNOWN


def _deciding(results: list[tuple[str, set[str]]], status: str) -> set[str]:
    """Identifiers of the sub-results whose status equals the outcome."""
    out: set[str] = set()
    for child_status, identifiers in results:
        if child_status == status:
            out |= identifiers
    return out


def _combine_and(results: list[tuple[str, set[str]]]) -> tuple[str, set[str]]:
    statuses = [status for status, _ in results]
    if STATUS_VIOLATION in statuses:
        status = STATUS_VIOLATION
    elif STATUS_UNKNOWN in statuses:
        status = STATUS_UNKNOWN
    else:
        status = STATUS_COMPLIANT
    return status, _deciding(results, status)


def _combine_or(results: list[tuple[str, set[str]]]) -> tuple[str, set[str]]:
    statuses = [status for status, _ in results]
    if STATUS_COMPLIANT in statuses:
        status = STATUS_COMPLIANT
    elif STATUS_UNKNOWN in statuses:
        status = STATUS_UNKNOWN
    else:
        status = STATUS_VIOLATION
    return status, _deciding(results, status)


def _evaluate(node: Any, allowed: set[str], denied: set[str]) -> tuple[str, set[str]]:
    """Return ``(status, deciding identifiers)`` for an expression subtree."""
    if isinstance(node, LicenseWithExceptionSymbol):
        # WITH is judged like AND: license and exception separately.
        return _combine_and(
            [
                _evaluate(node.license_symbol, allowed, denied),
                _evaluate(node.exception_symbol, allowed, denied),
            ]
        )
    if isinstance(node, LicenseSymbol):
        identifier = str(node)
        return _classify_leaf(identifier, allowed, denied), {identifier}
    if isinstance(node, AND):
        return _combine_and(
            [_evaluate(arg, allowed, denied) for arg in node.args]
        )
    if isinstance(node, OR):
        return _combine_or(
            [_evaluate(arg, allowed, denied) for arg in node.args]
        )
    raise ResolutionInputError(  # pragma: no cover - defensive
        f"unsupported SPDX expression element: {node!r}"
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def run_license_audit(
    resolved_raw: dict[str, str],
    licenses_raw: dict[str, str],
    allowed_raw: Iterable[str],
    denied_raw: Iterable[str],
) -> dict[str, Any]:
    """Classify every resolved package against the license policy."""
    resolved = parse_resolved(resolved_raw)
    expressions = parse_licenses(licenses_raw)
    allowed = parse_policy_identifiers(allowed_raw, "allowed")
    denied = parse_policy_identifiers(denied_raw, "denied")

    buckets: dict[str, list[dict[str, Any]]] = {
        STATUS_COMPLIANT: [],
        STATUS_VIOLATION: [],
        STATUS_UNKNOWN: [],
        STATUS_MISSING: [],
    }
    # Canonical-name order: each per-status list comes out stably sorted.
    for package in sorted(resolved):
        version = str(resolved[package])
        parsed = expressions.get(package)
        if parsed is None:
            entry: dict[str, Any] = {
                "package": package,
                "version": version,
                "expression": None,
                "status": STATUS_MISSING,
                "deciding_identifiers": [],
            }
        else:
            status, deciding = _evaluate(parsed, allowed, denied)
            entry = {
                "package": package,
                "version": version,
                "expression": str(parsed),
                "status": status,
                "deciding_identifiers": sorted(deciding),
            }
        buckets[entry["status"]].append(entry)

    return {
        "status": "ok",
        "summary": {
            "packages": len(resolved),
            STATUS_COMPLIANT: len(buckets[STATUS_COMPLIANT]),
            STATUS_VIOLATION: len(buckets[STATUS_VIOLATION]),
            STATUS_UNKNOWN: len(buckets[STATUS_UNKNOWN]),
            STATUS_MISSING: len(buckets[STATUS_MISSING]),
        },
        STATUS_COMPLIANT: buckets[STATUS_COMPLIANT],
        STATUS_VIOLATION: buckets[STATUS_VIOLATION],
        STATUS_UNKNOWN: buckets[STATUS_UNKNOWN],
        STATUS_MISSING: buckets[STATUS_MISSING],
    }
