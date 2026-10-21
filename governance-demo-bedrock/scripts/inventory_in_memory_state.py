"""Inventory of in-memory state in the governance engine (P0-12).

Finds instance attributes assigned an empty dict, list or set in __init__,
and module-level mutable containers, in lambdas/governance_engine/*.py. Each
finding must be classified in in_memory_state_classification.json as one of:

  CACHE           derived from durable state or code; losing it costs only time
  AUTHORITATIVE   the only copy of security-relevant state: must be backed by
                  durable storage in a deployed function
  REQUEST_SCOPED  lives for one request or one object's lifetime
  TEST_ONLY       used only by tests, demos or local experiments
  RESEARCH_ONLY   module not on the decision path (LEGACY_TO_AGENTCORE_MAPPING)
  CONFIG          code or static configuration (callbacks, constant tables)

Exit 1 when a finding is unclassified or a classification is stale, so new
in-memory authoritative state cannot appear unreviewed. Every AUTHORITATIVE
entry must name its durable backing ("durable") so the reviewer can check it.
"""

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "lambdas" / "governance_engine"
CLASSIFICATION = ROOT / "scripts" / "in_memory_state_classification.json"
VALID = {"CACHE", "AUTHORITATIVE", "REQUEST_SCOPED", "TEST_ONLY", "RESEARCH_ONLY", "CONFIG"}


def _is_empty_container(node) -> bool:
    if isinstance(node, (ast.Dict, ast.List, ast.Set)):
        return not getattr(node, "keys", None) and not getattr(node, "elts", None)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in {"dict", "list", "set", "defaultdict", "OrderedDict", "deque"} and not node.args
    return False


def findings():
    found = {}
    for path in sorted(ENGINE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            # module-level mutable containers (lower-case names; constants are UPPER)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    if isinstance(target, ast.Name) and value is not None and _is_empty_container(value):
                        found[f"{path.stem}:{target.id}"] = "module"
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "__init__":
                        for stmt in ast.walk(item):
                            target = value = None
                            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                                target, value = stmt.targets[0], stmt.value
                            elif isinstance(stmt, ast.AnnAssign):
                                target, value = stmt.target, stmt.value
                            if (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                                    and target.value.id == "self" and value is not None
                                    and _is_empty_container(value)):
                                found[f"{path.stem}:{node.name}.{target.attr}"] = "instance"
    return found


def main() -> int:
    current = findings()
    classified = json.loads(CLASSIFICATION.read_text(encoding="utf-8")) if CLASSIFICATION.exists() else {}
    problems = []
    for key in sorted(current):
        entry = classified.get(key)
        if entry is None:
            problems.append(f"unclassified: {key}")
        elif entry.get("class") not in VALID:
            problems.append(f"invalid class for {key}: {entry.get('class')}")
        elif entry.get("class") == "AUTHORITATIVE" and not entry.get("durable"):
            problems.append(f"authoritative state without a named durable backing: {key}")
    for key in sorted(set(classified) - set(current)):
        problems.append(f"stale classification (no longer found): {key}")
    if "--list" in sys.argv:
        for key in sorted(current):
            print(key, classified.get(key, {}).get("class", "UNCLASSIFIED"))
    counts = {}
    for key in current:
        cls = classified.get(key, {}).get("class", "UNCLASSIFIED")
        counts[cls] = counts.get(cls, 0) + 1
    print(json.dumps({"findings": len(current), "by_class": dict(sorted(counts.items()))}))
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
