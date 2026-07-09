# Architecture Documentation

Detailed technical documentation for the AI Runtime Governance framework. The [main README](../../README.md) shows the executive-level control plane diagram. These docs provide the full technical depth.

---

## Documents

| Document | What it covers |
|----------|---------------|
| [runtime-flow.md](runtime-flow.md) | The complete 20-step governance pipeline from request to response, with latency and short-circuit behavior |
| [control-plane.md](control-plane.md) | Agent registry, scope table, policy engine, risk engine, trust score, drift detector, human approval, evidence writer |
| [threat-defense.md](threat-defense.md) | Threat-to-control mapping: every attack vector matched to the module that defends against it |
| [evidence-pipeline.md](evidence-pipeline.md) | Decision to evidence record to hash chain to Object Lock to evidence graph to compliance package |
| [shadow-ai-discovery.md](shadow-ai-discovery.md) | Discovery, inventory, risk classification, register or quarantine, continuous monitoring |
| [supply-chain-governance.md](supply-chain-governance.md) | Model, prompt, tool, MCP server, and dataset provenance verification and approval |

---

## How to Read These

**Start with the README diagram** to understand the 4-layer story (request, governance, execution, evidence).

Then go deeper based on your role:

| Your role | Start with |
|-----------|-----------|
| Security reviewer | [threat-defense.md](threat-defense.md) |
| Compliance / audit | [evidence-pipeline.md](evidence-pipeline.md) |
| Developer / operator | [runtime-flow.md](runtime-flow.md) |
| Platform architect | [control-plane.md](control-plane.md) |
| Risk / governance | [shadow-ai-discovery.md](shadow-ai-discovery.md) + [supply-chain-governance.md](supply-chain-governance.md) |
