# Supply Chain Governance Architecture

Every component in the AI agent stack has a supply chain: the model, the prompts, the tools, the MCP servers, and the training datasets. Each is a potential point of compromise.

---

## Supply Chain Attack Surface

```
┌─────────────────────────────────────────────────────────────────────┐
│  WHAT CAN BE POISONED                                               │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ Base Model   │  │ System       │  │ Tools / MCP  │              │
│  │              │  │ Prompts      │  │ Servers      │              │
│  │ Pre-trained  │  │              │  │              │              │
│  │ weights may  │  │ Instructions │  │ External     │              │
│  │ contain      │  │ may be       │  │ services     │              │
│  │ backdoors    │  │ modified     │  │ may be       │              │
│  │              │  │ in transit   │  │ compromised  │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
│         │                 │                 │                       │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐              │
│  │ Fine-tuning  │  │ RAG Data     │  │ Datasets     │              │
│  │ Data         │  │ Sources      │  │              │              │
│  │              │  │              │  │ Training     │              │
│  │ Poisoned     │  │ Knowledge    │  │ data may be  │              │
│  │ examples     │  │ bases may    │  │ manipulated  │              │
│  │ sufficient   │  │ contain      │  │ to embed     │              │
│  │ for backdoor │  │ injections   │  │ behaviors    │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Governance Controls by Supply Chain Layer

### 1. Model Provenance

```
Model Selection
     │
     ▼
┌─────────────────────────────────────────┐
│  Verification Checklist                  │
│                                         │
│  [ ] Model source is AWS Bedrock        │
│      (managed, audited supply chain)    │
│  [ ] Model version pinned (not latest)  │
│  [ ] Model card reviewed                │
│  [ ] Safety benchmarks checked          │
│  [ ] No custom fine-tuning without      │
│      data provenance verification       │
│  [ ] Model registered in agent registry │
└─────────────────────────────────────────┘
```

| Control | Mechanism | Threat Addressed |
|---------|-----------|-----------------|
| Pin model version | CDK config: `amazon.nova-micro-v1:0` not `latest` | Version substitution |
| Use managed models | AWS Bedrock only (not self-hosted) | Unvetted model weights |
| Model registration | Agent registry tracks which model each agent uses | Model swap detection |
| Fine-tuning data audit | Provenance tags on all training examples | Data poisoning |

### 2. Prompt Governance

| Control | Mechanism | Threat Addressed |
|---------|-----------|-----------------|
| Prompt versioning | Git-tracked, code-reviewed | Unauthorized modification |
| Prompt integrity check | Hash comparison at runtime | Tampering in transit |
| System prompt isolation | Never exposed in agent output | Prompt extraction |
| Prompt change approval | Requires operator-level access | Social engineering |

### 3. Tool / MCP Server Governance

```
New Tool or MCP Server
     │
     ▼
┌─────────────────────────────────────────┐
│  Approval Workflow                       │
│                                         │
│  1. Tool metadata review                │
│     - Description does not contain      │
│       hidden instructions               │
│     - Schema matches documented API     │
│     - No undocumented parameters        │
│                                         │
│  2. MCP server authentication           │
│     - mTLS or OAuth2 required           │
│     - No anonymous access               │
│     - Scoped authorization tokens       │
│                                         │
│  3. Sandboxing verification             │
│     - Tool runs in isolated container   │
│     - No network access beyond          │
│       declared endpoints                │
│     - Filesystem isolated               │
│                                         │
│  4. Registration                         │
│     - Added to tool allowlist           │
│     - Metadata hash recorded            │
│     - Monitoring enabled                │
│                                         │
│  5. Continuous monitoring               │
│     - Metadata hash checked each call   │
│     - Response patterns baselined       │
│     - Anomaly detection active          │
└─────────────────────────────────────────┘
```

| Control | Mechanism | Threat Addressed |
|---------|-----------|-----------------|
| Tool allowlist (enum) | Only declared tools can be invoked | Unknown tool injection |
| Metadata hash | SHA-256 of tool description stored at registration | MCPTox metadata poisoning |
| MCP authentication | mTLS / OAuth2 mandatory | Server impersonation |
| Scoped authorization | Per-tool, per-agent access tokens | Over-privileged tools |
| Container sandboxing | Isolated execution, no lateral movement | Compromised tool pivot |
| Response validation | Scan all tool outputs for injection | Poisoned responses |

### 4. Dataset Governance

| Control | Mechanism | Threat Addressed |
|---------|-----------|-----------------|
| Data provenance tags | Every training example has source metadata | Untraceable poisoning |
| Data integrity hashes | SHA-256 per dataset file | Modification detection |
| Bias monitoring | Statistical analysis of dataset composition | Representation attacks |
| Access control | Dataset modification requires multi-party approval | Insider poisoning |
| Periodic re-validation | Monthly audit of data sources still trustworthy | Source compromise |

### 5. RAG Knowledge Base Governance

| Control | Mechanism | Threat Addressed |
|---------|-----------|-----------------|
| Content validation | Scan all documents before indexing | Injection in knowledge |
| Source attribution | Every chunk tagged with origin | Untrusted content mixing |
| Update approval | KB changes require operator sign-off | Unauthorized modification |
| Retrieval validation | Scan retrieved content before agent context | Runtime poisoning |
| Freshness monitoring | Alert on stale or modified source documents | Drift from truth |

---

## Supply Chain Integrity Verification (Runtime)

At every agent invocation, the following checks run:

```
1. Model version matches registered version?      ──▶ YES / DENY
2. Tool metadata hashes match registration?        ──▶ YES / DENY
3. MCP server certificates valid and trusted?      ──▶ YES / DENY
4. RAG knowledge base last-validated within SLA?   ──▶ YES / WARN
5. System prompt hash matches deployed version?    ──▶ YES / DENY
```

Any mismatch triggers immediate DENY and operator alert. The agent cannot operate with an unverified supply chain.

---

## Research Context

From [Malice in Agentland](https://arxiv.org/abs/2510.05159):
- "A small number of poisoned demonstrations is sufficient to backdoor an agent"
- >80% data leakage achieved through fine-tuning poisoning
- Environment poisoning is a novel vector unique to agentic systems

These findings make supply chain governance mandatory, not optional. A compromised model or dataset does not produce detectable anomalies at the prompt layer - the backdoor is in the weights.
