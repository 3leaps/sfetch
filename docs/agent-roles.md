# Agent Roles (Local Catalog)

This catalog mirrors the baseline roles from 3leaps Crucible so sfetch can work offline. Keep it lean and use only when needed.

## Recommended Roles (sfetch)

| Role       | Focus                                   | Use when                                                                 |
| ---------- | --------------------------------------- | ------------------------------------------------------------------------ |
| `devlead`  | Implementation and architecture          | Default role for features, fixes, refactors, and core design decisions   |
| `secrev`   | Security review                          | Signature verification, crypto changes, trust model, or supply-chain risk|
| `qa`       | Testing and validation                   | Designing tests, regression coverage, or quality gate enforcement        |
| `devrev`   | Code review                              | Four-eyes review for correctness and maintainability                     |
| `infoarch` | Documentation and schema clarity         | Docs updates, user-facing guidance, or standards alignment               |

## Optional Roles (only when needed)

| Role      | Focus                       | Use when                                               |
| --------- | --------------------------- | ------------------------------------------------------ |
| `cicd`    | CI/CD automation            | Workflow changes, pipeline tuning, release automation  |
| `releng`  | Release engineering         | Versioning, changelog, release notes                   |
| `dispatch`| Coordination and handoffs   | Cross-session routing and formal handoffs              |
| `prodmktg`| DevRelations / MarComms      | Messaging, positioning, and adoption guidance          |

## Source and References

- Baseline roles: `../crucible/config/agentic/roles/*.yaml`
- Marketing role: `../fulmenhq/crucible/config/agentic/roles/prodmktg.yaml`
- Catalog summary: `../crucible/config/agentic/roles/README.md`
- Online reference (when available): https://crucible.3leaps.dev/catalog/roles
