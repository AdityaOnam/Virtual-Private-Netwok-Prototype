# OnamVPN — Questions & Answers

A complete revision / viva preparation set for **OnamVPN — CN + OS Concept Laboratory**
(Aditya Onam, IIT Patna).

Everything here is derived from the code and documentation in this repository.
Where an answer names a file, the file exists; where it quotes a number, the number
comes from `config/`, a module constant, or a documented measurement.

## How to use this

| If you have… | Read |
|---|---|
| 10 minutes before a viva | [07-rapid-fire.md](07-rapid-fire.md) |
| An hour | [01-basics.md](01-basics.md) → [02-keywords.md](02-keywords.md) → [07-rapid-fire.md](07-rapid-fire.md) |
| A CN-focused examiner | [03-concepts-networking.md](03-concepts-networking.md) |
| An OS-focused examiner | [04-concepts-os.md](04-concepts-os.md) |
| A "show me the code" examiner | [05-code-architecture.md](05-code-architecture.md) |
| A hostile / probing examiner | [06-constructive.md](06-constructive.md) |

## Files

| File | Contents | Count |
|---|---|---|
| [01-basics.md](01-basics.md) | What the project is, how to run it, what each part does | 45 Q |
| [02-keywords.md](02-keywords.md) | Glossary-style: one keyword → definition → where it lives here | 120+ terms |
| [03-concepts-networking.md](03-concepts-networking.md) | Dissector, native tunnel, transport/ARQ/congestion, DNS, path & routing | 102 Q |
| [04-concepts-os.md](04-concepts-os.md) | Concurrency & GIL, scheduling, memory, resilience, IPC framing | 77 Q |
| [05-code-architecture.md](05-code-architecture.md) | Modules, classes, threading model, handlers, configuration | 55 Q |
| [06-constructive.md](06-constructive.md) | Defects found, limits, trade-offs, design critique, future work | 60 Q |
| [07-rapid-fire.md](07-rapid-fire.md) | One-line answers, every number in the project, command cheatsheet | 100+ |

## Source documents

These Q&A files summarise and cross-examine:

- [`README.md`](../../README.md) — project abstract, panels, verification, defects, gaps
- [`docs/concepts/`](../concepts/README.md) — nine per-module concept pages
- [`DOCUMENTATION.md`](../../DOCUMENTATION.md) — the original VPN client architecture
- [`docs/OPEN_ISSUE_tunnel.md`](../OPEN_ISSUE_tunnel.md) — the unresolved WARP tunnel bug
- the code itself under `netlab/`, `oslab/`, `vpn_core/`, `gui/`
