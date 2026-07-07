# Contributing

Thank you for your interest in contributing to AIGovernance.

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Install dependencies:
   ```bash
   cd governance-demo-bedrock
   python -m venv .venv
   source .venv/Scripts/activate  # Windows
   pip install -r requirements.txt
   ```

## Development Workflow

### Running Tests

```bash
python -m pytest tests/ -v
```

### Linting

```bash
pip install ruff
ruff check .
ruff format .
```

### CDK Synth (verify infrastructure changes)

```bash
npx cdk synth -c skip_cloudtrail=true --quiet
```

### Demo Validation

```bash
python test_datasets/run_demo_validation.py
```

## Pull Request Process

1. Ensure all tests pass (`pytest`, `ruff check`, `cdk synth`)
2. Update documentation if your change affects the architecture
3. Add tests for new functionality
4. Keep commits focused and atomic
5. Write clear commit messages (imperative mood, explain the "why")

## Architecture Decisions

- Follow the three-engine model (Preventive/Detective/Proactive)
- New governance checks go in the pipeline orchestrator
- New API endpoints go in the API router
- Infrastructure changes go in the appropriate construct module
- Lambda imports must be flat (no relative imports, no package-qualified)

## Code Style

- Python 3.12+
- No em dashes in any file
- Flat imports in Lambda code
- Type hints for public functions
- Minimal comments (code should be self-documenting)
