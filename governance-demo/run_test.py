"""Helper script to run property tests and write results to a file."""
import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/test_property_scope_enforcer.py", "-v", "--no-header", "--tb=short"]