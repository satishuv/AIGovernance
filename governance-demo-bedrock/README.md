# AI Agent Runtime Governance Framework

See the [main README](../README.md) at the repository root for full documentation.

## Quick Reference

```bash
# Activate environment
source .venv/Scripts/activate
pip install -r requirements.txt

# Deploy
npx cdk deploy -c skip_cloudtrail=true --require-approval never

# Validate
python test_datasets/run_demo_validation.py    # 21 scenarios
python -m pytest tests/ -v                     # 225 tests
```

## Key Paths

| Path | What it is |
|------|-----------|
| `lambdas/governance_engine/` | 72 governance modules ([MODULE_MAP](lambdas/governance_engine/MODULE_MAP.md)) |
| `docs/` | Architecture, security checklist, threat model, control catalog |
| `tests/` | 225 automated tests |
| `scripts/` | Evidence collection, benchmarks, demo |
| `governance_constructs/` | 6 CDK constructs (infrastructure-as-code) |
