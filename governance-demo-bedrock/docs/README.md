# Documentation

## Start Here

| You want to... | Read this |
|----------------|-----------|
| Understand what this is | [Main README](../README.md) |
| See the architecture | [Architecture diagrams](architecture/) |
| Review the security controls | [Security Checklist (93 controls)](AI_AGENT_SECURITY_CHECKLIST.md) |
| See the full control catalog | [Control Catalog (377 controls)](CONTROL_CATALOG.md) |
| Understand the threat model | [Threat Model](THREAT_MODEL.md) |
| Deploy it | [Main README - Quick Start](../README.md#quick-start) |
| Run the demo | [HIPAA Demo Guide](HIPAA_DEMO_GUIDE.md) |
| Collect evidence for audit | [Evidence Collection Guide](EVIDENCE_COLLECTION_GUIDE.md) |
| Understand how modules connect | [Module Map](../lambdas/governance_engine/MODULE_MAP.md) |
| Present to leadership | [Presentation Deck](PRESENTATION_DECK.md) |

---

## Architecture (deep technical docs)

| Document | Audience | Content |
|----------|----------|---------|
| [Runtime Flow](architecture/runtime-flow.md) | Developers | 20-step pipeline with latency budgets |
| [Control Plane](architecture/control-plane.md) | Platform architects | Registry, policy, risk, trust, approval |
| [Threat-Defense Mapping](architecture/threat-defense.md) | Security reviewers | Every attack mapped to its defense |
| [Evidence Pipeline](architecture/evidence-pipeline.md) | Compliance/audit | Decision to Object Lock to compliance package |
| [Shadow AI Discovery](architecture/shadow-ai-discovery.md) | Risk/governance | Find and govern unregistered AI |
| [Supply Chain](architecture/supply-chain-governance.md) | Security architects | Model/tool/MCP provenance |

---

## Research Foundation

| Document | Content |
|----------|---------|
| [AI-GBoK](AI_GOVERNANCE_BODY_OF_KNOWLEDGE.md) | AI Governance Body of Knowledge (20 domains) |
| [Security Checklist](AI_AGENT_SECURITY_CHECKLIST.md) | 93 controls from 22 peer-reviewed papers |
| [Threat Model](THREAT_MODEL.md) | Attack taxonomy and defense mapping |
| [Implementation Guide](IMPLEMENTATION_GUIDE.md) | How controls map to code |

