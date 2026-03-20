# Security Audit Skill for Claude Code

Enterprise-grade security audit plugin for Claude Code. One command (`/security-audit`) runs a 10-phase audit across any codebase — OWASP Top 10 SAST, secrets detection, dependency CVEs, IaC review, auth analysis, and auto-remediation. Automatically detects your platform type (traditional server, BaaS, fullstack, mobile, desktop, CMS, AI/ML, e-commerce, Web3, microservices, browser extensions) and activates the right security checks. Generates PDF reports with compliance mapping (SOC 2, PCI-DSS, HIPAA).

## Installation

### Option A: Copy to plugins directory

```bash
cp -r "Claude Security Audit Skill" ~/.claude/plugins/security-audit
```

### Option B: Symlink

```bash
ln -s "$(pwd)/Claude Security Audit Skill" ~/.claude/plugins/security-audit
```

## Usage

Run a full audit (all 10 phases):

```
/security-audit
/security-audit full
/security-audit all
```

Run a specific phase:

```
/security-audit secrets
/security-audit deps
/security-audit sast
/security-audit auth
/security-audit config
/security-audit iac
/security-audit logging
/security-audit discovery
```

Run a compliance-focused audit:

```
/security-audit --pci
/security-audit --hipaa
/security-audit --soc2
```

Verify prior fixes:

```
/security-audit recheck
/security-audit verify
```

## What It Does

### Platform-First Detection

Phase 1 classifies your project into one of 9 platform types, then activates only the relevant security checks:

| Platform Type | Example | What Gets Checked |
|---|---|---|
| **traditional-server** | Express, Django, Rails, Spring | Full server-side SAST, auth, sessions, headers |
| **baas** | Supabase, Firebase, Appwrite | RLS policies, security rules, client key scoping, storage |
| **fullstack-hybrid** | Next.js, Nuxt, SvelteKit | Both server + client checks, API route auth |
| **spa-plus-api** | React + separate backend | Client XSS, CORS, token handling, API security |
| **serverless** | Lambda, Vercel, Cloudflare Workers | Function auth, IAM, event injection |
| **static-site** | Hugo, Jekyll, Gatsby | Lightweight: deps, secrets, SRI only |
| **mobile-app** | React Native, Flutter | API keys in binary, cert pinning, storage |
| **monorepo** | Turborepo, Nx | Per-package audits, cross-package issues |
| **cli-library** | Published npm/pip package | Supply chain, no web checks |

### 10-Phase Audit

| # | Phase | Description |
|---|---|---|
| 1 | Asset Discovery | Classifies platform type, detects stack, frameworks, databases, APIs |
| 2 | Configuration & Hardening | CORS, headers, TLS, debug modes, cookie security, cloud misconfigs |
| 3 | Dependency & Supply Chain | `npm audit` / `pip audit` / lockfile integrity / CVE checks / dependency confusion |
| 4 | Code-Level SAST | OWASP Top 10 + API-specific: SQLi, XSS, SSRF, GraphQL depth, mass assignment |
| 5 | IaC Review | Docker, Terraform, Kubernetes, CloudFormation, CI/CD pipeline security |
| 6 | Secrets & Credentials | 30+ regex patterns for API keys, tokens, passwords in code and git history |
| 7 | Auth & Access Control | JWT, sessions, RBAC, OAuth + Supabase RLS / Firebase rules / BaaS policies |
| 8 | Logging & Monitoring | Security event logging, log injection, PII in logs, alerting |
| 9 | Report & Remediation | Severity scoring, CWE/OWASP mapping, auto-fix, markdown report generation |
| 10 | PDF Report | Professional styled PDF (or HTML fallback) for sharing and compliance |

## Auto-Remediation

- **Low / Medium findings** are auto-fixed silently (security headers, `.gitignore`, cookie flags, etc.)
- **High / Critical findings** are auto-fixed with user confirmation (SQL parameterization, auth middleware, etc.)
- **Safety guardrails** prevent fixes that could break functionality — max 15 lines per fix, no multi-file refactors, re-read after fix to verify syntax

## Output

Three report files are generated in the project root:

| File | Format | Description |
|---|---|---|
| `SECURITY-AUDIT-REPORT.md` | Markdown | Primary report — always generated |
| `SECURITY-AUDIT-REPORT.pdf` | PDF | Styled, print-ready report (when PDF tools available) |
| `SECURITY-AUDIT-REPORT.html` | HTML | Fallback when no PDF tool is installed (open in browser, print to PDF) |

Reports include:

- Executive summary with risk rating and top 3 critical findings
- Unicode box-drawing styled finding cards with CVSS scores
- Findings organized by severity (Critical → Info)
- CWE, OWASP Top 10, SOC 2, PCI-DSS, and HIPAA compliance mapping
- Remediation status (auto-fixed vs. manual)
- Phase-by-phase status dashboard
- Re-audit instructions

## False Positive Handling

The skill includes a centralized false positive registry that:

- Excludes test files, fixtures, mocks, vendored code, and generated output
- Filters placeholder values (`your-api-key`, `changeme`, `TODO`)
- Applies phase-specific context rules (CORS wildcard is fine on a public API without credentials)
- Adjusts severity based on context (test code, dev config, compensating controls)

## Architecture

```
Claude Security Audit Skill/
├── .claude-plugin/
│   └── plugin.json                            # Plugin manifest
├── skills/
│   └── security-audit/
│       ├── SKILL.md                           # Main orchestrator (10 phases)
│       ├── references/
│       │   ├── # ── Core References (always loaded) ──────────
│       │   ├── owasp-top-10-checks.md         # SAST patterns per language/framework
│       │   ├── api-security-checks.md         # REST, GraphQL, WebSocket, gRPC
│       │   ├── iac-security-checks.md         # Docker/Terraform/K8s/CloudFormation
│       │   ├── secrets-patterns.md            # 30+ regex patterns for secrets
│       │   ├── dependency-audit-guide.md      # CVE checking, lockfile integrity
│       │   ├── auth-and-access-checks.md      # JWT, session, RBAC, OAuth
│       │   ├── config-hardening-checks.md     # TLS, CORS, headers, cloud misconfigs
│       │   ├── logging-monitoring-checks.md   # Security event logging, alerting
│       │   ├── severity-scoring.md            # CVSS-style scoring rubric
│       │   ├── compliance-mapping.md          # CWE/OWASP/SOC2/HIPAA/PCI-DSS
│       │   ├── auto-remediation-patterns.md   # Before/after code transforms
│       │   ├── false-positives.md             # False positive filtering rules
│       │   ├── pdf-report-guide.md            # PDF generation + CSS styling
│       │   ├── # ── Platform-Specific References ─────────
│       │   ├── baas-security-checks.md        # Supabase, Firebase, Appwrite, PocketBase
│       │   ├── wordpress-cms-checks.md        # WordPress, Drupal, Joomla
│       │   ├── electron-desktop-checks.md     # Electron, Tauri desktop apps
│       │   ├── mobile-app-checks.md           # React Native, Flutter, iOS, Android
│       │   ├── ai-ml-security-checks.md       # LLM, ML models, data pipelines
│       │   ├── ecommerce-payments-checks.md   # Stripe, PayPal, Shopify, PCI-DSS
│       │   ├── browser-extension-checks.md    # Chrome, Firefox, Safari extensions
│       │   ├── microservices-checks.md        # Service mesh, mTLS, message queues
│       │   └── web3-smart-contract-checks.md  # Solidity, Solana, dApp frontends
│       └── assets/
│           └── report-template.md             # Markdown template for final report
├── agents/
│   └── security-scanner.md                    # Sub-agent for parallelized scanning
├── README.md
├── GITHUB-DESCRIPTION.md
└── LICENSE
```

Key design:
- **Platform-first routing**: Phase 1 classifies the project, then only loads relevant reference files
- **Multi-type support**: A project can be `fullstack-hybrid` + `baas` + `ecommerce` + `ai-ml` simultaneously
- **Progressive loading**: Reference files are only read when their phase runs
- **Parallel scanning**: Large codebases (>200 files) are split into batches and scanned by multiple Sonnet agents
- **Graceful degradation**: Falls back to Grep-based analysis when CLI tools aren't installed; falls back to HTML when PDF tools aren't available
- **Stack-aware**: Phase 1 builds a STACK_PROFILE that all subsequent phases use to skip irrelevant checks

## Requirements

- Claude Code CLI
- The skill gracefully degrades when external tools aren't available:
  - `npm audit` / `pip-audit` / `bundle audit` etc. — falls back to pattern matching
  - `puppeteer` / `pandoc` / `wkhtmltopdf` — falls back to HTML report

## License

MIT
