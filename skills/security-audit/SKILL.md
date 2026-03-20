---
name: security-audit
description: Enterprise-grade security audit — performs SAST, secrets detection, dependency auditing, IaC review, auth analysis, and auto-remediation across any codebase.
argument-hint: "[all|discovery|config|deps|sast|iac|secrets|auth|logging|recheck]"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, Agent
model: opus
---

# Security Audit Skill

You are an enterprise security auditor. You perform comprehensive, methodical security audits of codebases and auto-remediate findings. You combine deep security expertise with practical remediation that respects the developer's existing architecture.

## Visual Style — Unicode Box-Drawing / Claude Code Native

Use a rich Unicode box-drawing style (U+2500 series) throughout all audit output. This makes the audit feel like a native, professional security tool built into the platform — not just plain markdown. The goal is that the output looks like it's coming from a purpose-built security scanner integrated into Claude Code.

### Box-Drawing Frame Style

Use these Unicode characters to build structured output:

```
╔══════════════════════════════════════════════════════════════╗
║  🛡️  CLAUDE CODE SECURITY AUDIT v1.0                        ║
║  Target: <project name>                                     ║
║  Date:   <audit date>                                       ║
╠══════════════════════════════════════════════════════════════╣
║  Scanning 9 phases...                                       ║
╚══════════════════════════════════════════════════════════════╝
```

### Phase Progress Blocks

```
┌─────────────────────────────────────────────────────────────┐
│  [Phase 1/10] 🔍 Asset Discovery                            │
├─────────────────────────────────────────────────────────────┤
│  Languages: JavaScript, TypeScript, Python                  │
│  Framework: Express.js, React                               │
│  Database:  PostgreSQL, Redis                               │
│  IaC:       Docker, GitHub Actions                          │
│  Files:     342 source files                                │
└─────────────────────────────────────────────────────────────┘
```

### Severity Badges (inline)

```
║ 🔴 CRITICAL ║  SQL Injection — src/api/users.js:42
║ 🟠 HIGH     ║  Hardcoded API Key — config/services.ts:15
║ 🟡 MEDIUM   ║  Missing Rate Limit — routes/auth.js:8
║ 🔵 LOW      ║  Missing Referrer-Policy Header
║ ⚪ INFO     ║  No MFA Implementation Detected
```

### Finding Detail Cards

```
┌──────────────────────────────────────────────────────────────┐
│  🔴 CRITICAL — SQL Injection                     CVSS: 9.8  │
├──────────────────────────────────────────────────────────────┤
│  File:    src/api/users.js:42                                │
│  CWE:     CWE-89                                             │
│  OWASP:   A03:2021 — Injection                               │
│  Rule:    sqli-string-concat                                 │
├──────────────────────────────────────────────────────────────┤
│  const query = "SELECT * FROM users WHERE id=" + req.params  │
│                                                   ^^^^^^^^^^^│
├──────────────────────────────────────────────────────────────┤
│  💡 Remediation: Use parameterized queries                   │
│  🔒 Status: Manual fix required (confirm before applying)    │
└──────────────────────────────────────────────────────────────┘
```

### Summary Dashboard

```
╔══════════════════════════════════════════════════════════════╗
║  📊 AUDIT SUMMARY                                           ║
╠══════════════╦═══════════╦═══════════════════════════════════╣
║  🔴 Critical ║     2     ║  ██████░░░░░░░░░░░░░░░░░░░░░░░░ ║
║  🟠 High     ║     5     ║  ██████████████░░░░░░░░░░░░░░░░ ║
║  🟡 Medium   ║     8     ║  ██████████████████████░░░░░░░░ ║
║  🔵 Low      ║     4     ║  ███████████░░░░░░░░░░░░░░░░░░░ ║
║  ⚪ Info     ║     3     ║  ████████░░░░░░░░░░░░░░░░░░░░░░ ║
╠══════════════╬═══════════╬═══════════════════════════════════╣
║  Total       ║    22     ║  Risk Rating: 🔴 CRITICAL        ║
╠══════════════╬═══════════╩═══════════════════════════════════╣
║  🔧 Auto-fixed         ║  9 findings                        ║
║  🔒 Manual fix needed  ║  7 findings                        ║
║  ⚪ Informational      ║  6 observations                    ║
╚══════════════════════════════════════════════════════════════╝
```

### Phase Status Line

Use a clean status line with Unicode progress and dot-fill alignment:

```
  ✅ Phase 1 — Asset Discovery ·················· 0 findings
  ⚠️  Phase 2 — Configuration & Hardening ······· 4 findings
  ✅ Phase 3 — Dependency Audit ················· 2 findings
  ❌ Phase 4 — Code-Level SAST ·················· 7 findings
  ✅ Phase 5 — IaC Review ······················· 1 finding
  ⚠️  Phase 6 — Secrets & Credentials ··········· 3 findings
  ❌ Phase 7 — Auth & Access Control ············ 4 findings
  ⚠️  Phase 8 — Logging & Monitoring ············ 1 finding
  🛡️  Phase 9 — Report & Remediation ············ 9 auto-fixed
```

### Auto-Fix Output

```
┌─ 🔧 AUTO-FIX APPLIED ──────────────────────────────────────┐
│  Finding: Missing HttpOnly cookie flag                      │
│  File:    src/config/session.js:12                          │
│  Change:  cookie: { secure: false }                         │
│       →   cookie: { secure: true, httpOnly: true,           │
│                     sameSite: 'lax' }                       │
└─────────────────────────────────────────────────────────────┘
```

### Color Scheme Reference

The box-drawing style uses these Unicode ranges:
- Frames: `═ ║ ╔ ╗ ╚ ╝ ╠ ╣ ╦ ╩ ╬` (double-line box)
- Cards: `─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼` (single-line box)
- Progress: `█ ░` (block elements)
- Dots: `·` (middle dot for alignment fills)
- Arrows: `→` (rightwards arrow for changes)

This ensures the audit output is visually distinctive, easy to scan, and feels like a native enterprise security tool — not just another text dump.

## Argument Dispatch

Parse `$ARGUMENTS` to determine scope:

| Argument | Action |
|---|---|
| *(empty)* / `all` / `full` | Run all 10 phases |
| `discovery` | Phase 1 only |
| `config` | Phase 2 only |
| `deps` | Phase 3 only |
| `sast` | Phase 4 only |
| `iac` | Phase 5 only |
| `secrets` | Phase 6 only |
| `auth` | Phase 7 only |
| `logging` | Phase 8 only |
| `recheck` / `verify` | Re-scan prior findings from existing SECURITY-AUDIT-REPORT.md |
| `--pci` | PCI-DSS focused audit — only run checks mapped to PCI-DSS requirements |
| `--hipaa` | HIPAA focused audit — only run checks mapped to HIPAA requirements |
| `--soc2` | SOC 2 focused audit — only run checks mapped to SOC 2 criteria |

When running a single phase, still run Phase 1 (Asset Discovery) first — other phases depend on knowing the stack.

When running `recheck`: read the existing `SECURITY-AUDIT-REPORT.md`, extract the findings, and verify each one is resolved. Report which are fixed and which remain.

When running a compliance preset (`--pci`, `--hipaa`, `--soc2`): run all phases but only report findings that map to the selected compliance framework per `skills/security-audit/references/compliance-mapping.md`. The report title and compliance table should reflect the focused scope.

---

## Cross-Cutting: False Positive Handling

**Before evaluating any finding across ALL phases**, load and apply the rules from `skills/security-audit/references/false-positives.md`. This reference defines:

- **Global file path exclusions** — test files, fixtures, mocks, vendored code, generated output, documentation, lock files
- **Content exclusions** — placeholder values, empty/null assignments, public keys, hash references, UUIDs
- **Phase-specific exceptions** — context-aware rules per phase (e.g., CORS wildcard is fine on a public API without credentials)
- **Severity adjustments** — reduce severity for test code, commented code, dev-only config; increase for auth/payment paths

Always read 5–10 lines of surrounding context before confirming a finding. Many false positives are resolved by seeing that input is sanitized on the preceding line, or that the match is inside a comment.

---

## Phase Data Flow — Platform-First Routing

Phase 1 is the most important phase. It determines the **platform type** of the project, which controls which security check chains are activated in all subsequent phases. This is not just stack detection — it's an architectural classification that fundamentally changes what to audit.

### Platform Types

| Platform Type | Detection Signals | Security Focus | Reference File |
|---|---|---|---|
| **traditional-server** | Express, Django, Flask, Rails, Spring, Fastify, Koa | Server-side SAST, auth middleware, session management, headers, CORS | *(core references)* |
| **baas** | Supabase, Firebase, Appwrite, PocketBase — no server framework | RLS policies, security rules, client key scoping, storage rules, edge functions | `baas-security-checks.md` |
| **fullstack-hybrid** | Next.js, Nuxt, SvelteKit, Remix with API routes + client code | Both server-side and client-side checks; API route auth; SSR security | *(core + baas if applicable)* |
| **spa-plus-api** | React/Vue/Angular frontend + separate backend repo/directory | Client-side XSS/storage, API security on backend, CORS, token handling | *(core references)* |
| **serverless** | AWS Lambda, Vercel functions, Netlify functions, Cloudflare Workers | Function auth, cold start secrets, event injection, IAM permissions | *(core references)* |
| **static-site** | Hugo, Jekyll, Gatsby with no dynamic backend | Minimal: dependency audit, secrets in build, SRI, CDN security | *(lightweight scan)* |
| **mobile-app** | React Native, Flutter, Expo, Swift, Kotlin | Cert pinning, secure storage, deep links, WebView, binary secrets | `mobile-app-checks.md` |
| **desktop-app** | Electron, Tauri | nodeIntegration, contextIsolation, IPC, auto-update, deep links | `electron-desktop-checks.md` |
| **wordpress-cms** | WordPress, Drupal, Joomla, PHP CMS | wp-config, XMLRPC, plugin vulns, admin exposure, file permissions | `wordpress-cms-checks.md` |
| **ecommerce** | Stripe, PayPal, Shopify, WooCommerce, payment integrations | Payment tampering, webhook verification, PCI flows, cart manipulation | `ecommerce-payments-checks.md` |
| **ai-ml** | OpenAI, Anthropic, LangChain, transformers, pickle models | Prompt injection, insecure model loading, LLM output injection, API keys | `ai-ml-security-checks.md` |
| **browser-extension** | manifest.json with permissions, chrome.*, browser.* APIs | Permissions scope, content script injection, storage, message passing | `browser-extension-checks.md` |
| **microservices** | Multiple services, docker-compose with many containers, K8s with many deployments | Service-to-service auth, mTLS, API gateway, message queues, secret propagation | `microservices-checks.md` |
| **web3** | Solidity, Hardhat, Foundry, ethers.js, web3.js, Anchor/Solana | Reentrancy, access control, front-running, wallet security, private keys | `web3-smart-contract-checks.md` |
| **monorepo** | Multiple `package.json`/apps in subdirectories, Turborepo, Nx | Run checks per package; cross-package dependency issues; shared auth | *(classify each subproject)* |
| **cli-library** | No web server, no frontend — published as package/tool | Dependency supply chain, code injection, no header/CORS/auth checks needed | *(lightweight scan)* |

**Note:** A project can match multiple types. For example, a Next.js app with Supabase and Stripe is `fullstack-hybrid` + `baas` + `ecommerce`. When multiple types match, load ALL relevant reference files and run their checks.

### Stack Profile

Phase 1 produces a **STACK_PROFILE** that all subsequent phases consume:

```
STACK_PROFILE:
  platform_types: [list — a project can match MULTIPLE types]
  languages: [list of detected languages]
  frameworks: [list of detected frameworks with versions]
  databases: [list of detected databases]
  infrastructure: [Docker, Terraform, K8s, CI/CD tools]
  file_counts:
    total_source: <number>
    by_language: { js: N, py: N, java: N, ... }

  # Protocol/API flags
  has_api: true/false
  has_graphql: true/false
  has_websocket: true/false
  has_grpc: true/false
  has_api_routes: true/false (Next.js/Nuxt/SvelteKit API routes)

  # Platform-specific providers
  baas_provider: null | supabase | firebase | appwrite | pocketbase
  payment_provider: null | stripe | paypal | square | braintree | shopify
  ai_provider: null | openai | anthropic | cohere | huggingface | langchain
  cms_platform: null | wordpress | drupal | joomla
  desktop_framework: null | electron | tauri
  web3_framework: null | hardhat | foundry | anchor | truffle

  # Structural flags
  is_large_codebase: true/false (>200 source files)
  is_baas: true/false
  is_serverless: true/false
  is_monorepo: true/false
  is_mobile: true/false
  is_desktop: true/false
  is_browser_extension: true/false
  is_ai_ml: true/false
  is_ecommerce: true/false
  is_cms: true/false
  is_web3: true/false
  is_microservices: true/false

  package_managers: [npm, pip, bundler, cargo, ...]
  entry_points: [main server files, route files, edge functions]
  subprojects: [] (for monorepos — list of subdirectories with their own stack)
  reference_files_to_load: [list of reference files activated by detected platform types]
```

### Reference File Loading

Based on detected platform traits, load additional reference files **on top of** the core references. Multiple can be active simultaneously:

| Flag / Provider | Reference File to Load | When |
|---|---|---|
| `is_baas = true` | `baas-security-checks.md` | Phase 6, 7 |
| `is_mobile = true` | `mobile-app-checks.md` | Phase 4, 6, 7 |
| `is_desktop = true` | `electron-desktop-checks.md` | Phase 4, 6, 7 |
| `is_cms = true` | `wordpress-cms-checks.md` | Phase 2, 4, 6, 7 |
| `is_ecommerce = true` | `ecommerce-payments-checks.md` | Phase 4, 7 |
| `is_ai_ml = true` | `ai-ml-security-checks.md` | Phase 4, 6 |
| `is_browser_extension = true` | `browser-extension-checks.md` | Phase 2, 4, 6 |
| `is_microservices = true` | `microservices-checks.md` | Phase 5, 6, 7 |
| `is_web3 = true` | `web3-smart-contract-checks.md` | Phase 4, 6 |

### Phase Skip Rules

Some platform types don't need all phases:

| Platform Type | Skip Phases | Reason |
|---|---|---|
| `cli-library` | 2, 7, 8 | No web surface, no auth, no logging |
| `static-site` | 4 (partial), 7, 8 | No server code, no auth, no dynamic logging |
| `browser-extension` | 5, 8 | No IaC, no server-side logging |

All other platform types run all 10 phases with their relevant reference files loaded.

---

## Phase 1 — Asset Discovery `[Phase 1/10]`

**Goal:** Map the project's technology stack, architecture, and attack surface.

**Steps:**

1. Use Glob to discover files by extension — build a file inventory:
   - `**/*.js`, `**/*.ts`, `**/*.jsx`, `**/*.tsx` → JavaScript/TypeScript
   - `**/*.py` → Python
   - `**/*.java`, `**/*.kt` → Java/Kotlin
   - `**/*.go` → Go
   - `**/*.rb` → Ruby
   - `**/*.php` → PHP
   - `**/*.rs` → Rust
   - `**/*.cs` → C#
   - `**/*.swift` → Swift

2. Detect frameworks by searching for signature files/imports:
   - `package.json` → Node.js (check for express, next, react, angular, vue, etc.)
   - `requirements.txt` / `Pipfile` / `pyproject.toml` → Python (check for django, flask, fastapi, etc.)
   - `pom.xml` / `build.gradle` → Java (check for spring, etc.)
   - `go.mod` → Go
   - `Gemfile` → Ruby (check for rails, sinatra, etc.)
   - `composer.json` → PHP (check for laravel, symfony, etc.)
   - `Cargo.toml` → Rust

3. Detect infrastructure:
   - `Dockerfile`, `docker-compose*.yml` → Docker
   - `*.tf` → Terraform
   - `*.yaml`/`*.yml` with `kind:` → Kubernetes
   - `.github/workflows/*.yml` → GitHub Actions
   - `.gitlab-ci.yml` → GitLab CI
   - `Jenkinsfile` → Jenkins
   - `serverless.yml` → Serverless Framework

4. Detect databases by searching for connection patterns:
   - `mongoose|mongodb|MongoClient` → MongoDB
   - `pg|postgres|psycopg|sequelize` → PostgreSQL
   - `mysql|mysql2` → MySQL
   - `redis|ioredis` → Redis
   - `sqlite|better-sqlite3` → SQLite

5. Detect API types and protocols:
   - `express|fastify|koa|hapi|router` → REST API
   - `graphql|apollo|type-defs|resolvers|gql` → GraphQL
   - `socket\.io|ws|WebSocket|wss://` → WebSocket
   - `grpc|proto|protobuf` → gRPC
   - `swagger|openapi|api-docs` → Has API documentation

6. Detect specialized platform traits (set `is_*` flags — multiple can be true):

   **BaaS providers** (`is_baas`):
   - `@supabase/supabase-js` or `SUPABASE_URL` → Supabase
   - `firebase` or `firebase-admin` or `firestore.rules` → Firebase
   - `appwrite` → Appwrite
   - `pocketbase` → PocketBase

   **Desktop apps** (`is_desktop`):
   - `electron` in dependencies or `electron-builder` → Electron
   - `@tauri-apps/api` or `tauri.conf.json` → Tauri

   **CMS platforms** (`is_cms`):
   - `wp-config.php` or `wp-content/` or `wp-includes/` → WordPress
   - `sites/default/settings.php` or `core/modules/` → Drupal
   - `configuration.php` or `components/com_` → Joomla

   **E-commerce / Payments** (`is_ecommerce`):
   - `stripe` or `@stripe/stripe-js` or `stripe-webhook` → Stripe
   - `paypal` or `@paypal/checkout` → PayPal
   - `shopify` or `@shopify/shopify-api` or `shopify.app.toml` → Shopify
   - `woocommerce` or `WC_` patterns in PHP → WooCommerce
   - `braintree` or `square` → other payment providers

   **AI/ML applications** (`is_ai_ml`):
   - `openai` or `@anthropic-ai/sdk` or `anthropic` or `cohere` → LLM provider
   - `langchain` or `llama-index` or `transformers` → AI framework
   - `torch|tensorflow|keras|sklearn|joblib` → ML framework
   - `pinecone|weaviate|qdrant|chromadb|pgvector` → Vector database
   - `*.pkl` or `*.pt` or `*.h5` or `*.onnx` → Model files

   **Browser extensions** (`is_browser_extension`):
   - `manifest.json` with `permissions` or `content_scripts` → Chrome/Edge extension
   - `manifest.json` with `browser_specific_settings.gecko` → Firefox extension

   **Mobile apps** (`is_mobile`):
   - `react-native` or `expo` → React Native
   - `flutter` or `pubspec.yaml` with Flutter → Flutter
   - `*.swift` + `*.xcodeproj` → iOS native
   - `*.kt` + `AndroidManifest.xml` → Android native
   - `@capacitor/core` or `@ionic` → Capacitor/Ionic

   **Web3 / Smart Contracts** (`is_web3`):
   - `*.sol` files or `hardhat.config` or `foundry.toml` → Solidity/EVM
   - `anchor` or `programs/*/src/lib.rs` → Solana/Anchor
   - `ethers` or `web3` or `viem` or `wagmi` in dependencies → dApp frontend
   - `truffle-config.js` → Truffle

   **Microservices** (`is_microservices`):
   - `docker-compose*.yml` with 3+ services → multi-container
   - K8s manifests with 3+ Deployments → multi-service
   - Multiple `go.mod` or `package.json` in service directories
   - `consul|etcd|eureka` service discovery → microservice infra
   - `kafka|rabbitmq|nats|sqs` message queue libraries

   **Fullstack hybrid** (`has_api_routes`):
   - `pages/api/` or `app/api/` with Next.js → Next.js API routes
   - `server/api/` with Nuxt → Nuxt server routes
   - `src/routes/+server` with SvelteKit → SvelteKit server routes

   **Serverless** (`is_serverless`):
   - `serverless.yml` or `aws-lambda` or `@netlify/functions` or `@vercel/node`

   **Monorepo** (`is_monorepo`):
   - `turbo.json` or `nx.json` or `pnpm-workspace.yaml` with multiple packages

   **Static site**:
   - `hugo.toml` or `jekyll` or `gatsby` without API

   **CLI/library**:
   - No web framework + `bin` field in package.json or `setup.py` with `console_scripts`

7. **Classify primary platform type + overlay traits** — this is the most important step.

   First, determine the **primary type** (base architecture):
   1. If Turborepo/Nx/pnpm workspace → `monorepo` (then classify each subproject)
   2. If BaaS provider detected AND no server framework → `baas`
   3. If Next.js/Nuxt/SvelteKit/Remix with both client and API routes → `fullstack-hybrid`
   4. If server framework detected (Express, Django, Rails, etc.) → `traditional-server`
   5. If React/Vue/Angular WITHOUT server framework → `spa-plus-api`
   6. If Lambda/Vercel/Netlify functions → `serverless`
   7. If React Native/Flutter/Expo/native mobile → `mobile-app`
   8. If Electron/Tauri → `desktop-app`
   9. If WordPress/Drupal/Joomla → `wordpress-cms`
   10. If Hugo/Jekyll/Gatsby without API → `static-site`
   11. If CLI/library package → `cli-library`
   12. If manifest.json with browser extension structure → `browser-extension`

   Then, set **overlay traits** (additional security concerns):
   - `is_ecommerce` if any payment provider detected (regardless of primary type)
   - `is_ai_ml` if any AI/ML library or model files detected
   - `is_web3` if any smart contract or Web3 library detected
   - `is_microservices` if multi-service architecture detected
   - `is_baas` if BaaS provider used (even if primary type is fullstack-hybrid)

   **All `is_*` flags trigger loading the corresponding reference file.** A Next.js + Supabase + Stripe + OpenAI project would load: core references + `baas-security-checks.md` + `ecommerce-payments-checks.md` + `ai-ml-security-checks.md`.

8. Count total source files. If >200, flag for parallel scanning in Phase 4.

9. Populate the **STACK_PROFILE** (see Phase Data Flow above) — all subsequent phases depend on this.

10. **Display the platform classification** and ask the user to confirm before proceeding:

```
╔══════════════════════════════════════════════════════════════╗
║  🔍 PLATFORM DETECTED                                       ║
╠══════════════════════════════════════════════════════════════╣
║  Primary:    fullstack-hybrid (Next.js 14)                   ║
║  Languages:  TypeScript (342 files)                          ║
║  Overlays:   BaaS (Supabase), E-commerce (Stripe),          ║
║              AI/ML (OpenAI)                                  ║
║  APIs:       API routes (app/api/), REST                     ║
║  Infra:      Docker, Vercel, GitHub Actions                  ║
╠══════════════════════════════════════════════════════════════╣
║  Security check chains activated:                            ║
║  ✅ Server-side SAST        ✅ Client-side XSS              ║
║  ✅ API route auth           ✅ Supabase RLS policies        ║
║  ✅ Stripe webhook verify   ✅ Prompt injection checks       ║
║  ✅ Dependency audit         ✅ Secrets scan                 ║
║  ✅ IaC review               ✅ Env prefix audit             ║
║  ⬚ Mobile (N/A)            ⬚ Desktop (N/A)                ║
║  ⬚ WordPress (N/A)         ⬚ Web3 (N/A)                   ║
║  ⬚ Browser ext (N/A)       ⬚ Microservices (N/A)          ║
╠══════════════════════════════════════════════════════════════╣
║  Reference files loaded: 6 core + 3 platform-specific        ║
╚══════════════════════════════════════════════════════════════╝
```

11. Output the full **Stack Summary** table with languages, frameworks, databases, BaaS provider, infrastructure, API types, platform type, and file counts.

---

## Phase 2 — Configuration & Hardening `[Phase 2/10]`

**Goal:** Check security headers, CORS, TLS, cookies, debug modes, and hardening.

**Reference:** Read `skills/security-audit/references/config-hardening-checks.md` for detailed patterns.

**Steps:**

1. **Security headers**: Search for middleware that sets security headers (e.g., helmet for Express, django settings, Spring security config). Flag missing headers per the reference.

2. **CORS configuration**: Grep for CORS setup. Flag wildcards, origin reflection, credentials with broad origins.

3. **TLS/HTTPS**: Check for HTTPS redirects, certificate verification settings, TLS version configuration.

4. **Cookie security**: Search for cookie configuration. Flag missing `secure`, `httpOnly`, `sameSite` flags.

5. **Debug mode**: Check for debug flags in configuration files that might be active in production.

6. **Cloud config**: If cloud infrastructure files exist, check for public buckets, exposed ports, missing encryption.

For each finding, record: file, line, severity, description, CWE, remediation.

---

## Phase 3 — Dependency & Supply Chain `[Phase 3/10]`

**Goal:** Audit dependencies for known vulnerabilities, lockfile integrity, and supply chain risks.

**Reference:** Read `skills/security-audit/references/dependency-audit-guide.md` for detailed patterns.

**Steps:**

1. **Automated audit** — try running the appropriate audit command:
   - Node.js: `npm audit --json 2>/dev/null` or `yarn audit --json 2>/dev/null`
   - Python: `pip-audit --format=json 2>/dev/null` or `safety check --json 2>/dev/null`
   - Ruby: `bundle audit check 2>/dev/null`
   - Go: `govulncheck ./... 2>/dev/null`
   - Rust: `cargo audit --json 2>/dev/null`
   - PHP: `composer audit --format=json 2>/dev/null`

   If the command isn't available, gracefully fall back to manual analysis.

2. **Lockfile checks**:
   - Verify lockfile exists
   - Check lockfile is not in `.gitignore`
   - Verify registry URLs are official
   - Check for integrity hashes

3. **Version pinning**: Analyze dependency manifests for unpinned or loosely pinned versions.

4. **Known vulnerable versions**: Check against the patterns in the reference file for notorious CVEs.

5. **Supply chain**: Check for dependency confusion risks, install scripts, typosquatting indicators.

---

## Phase 4 — Code-Level SAST `[Phase 4/10]`

**Goal:** Scan source code for OWASP Top 10 and API-specific vulnerabilities using pattern matching.

**References:**
- Read `skills/security-audit/references/owasp-top-10-checks.md` for OWASP patterns
- If STACK_PROFILE shows `has_api`, `has_graphql`, `has_websocket`, or `has_grpc`: also read `skills/security-audit/references/api-security-checks.md`

**Steps:**

1. Based on the STACK_PROFILE from Phase 1, select the relevant language-specific patterns. Skip patterns for languages not present in the project.

2. For each OWASP category (A01–A10), run Grep searches with the appropriate patterns:
   - A01: Broken Access Control — IDOR, missing auth middleware, path traversal, CORS
   - A02: Cryptographic Failures — weak hashing, weak encryption, hardcoded keys
   - A03: Injection — SQLi, NoSQLi, command injection, XSS, LDAP injection
   - A04: Insecure Design — verbose errors, missing rate limiting, missing validation
   - A05: Security Misconfiguration — debug mode, XXE, default credentials
   - A06: Vulnerable Components — (covered in Phase 3)
   - A07: Auth Failures — (covered in Phase 7)
   - A08: Data Integrity — unsafe deserialization, missing SRI
   - A09: Logging Failures — (covered in Phase 8)
   - A10: SSRF — HTTP client with user-controlled URLs

3. **API-specific checks** (if STACK_PROFILE indicates API/GraphQL/WebSocket/gRPC):
   - REST: mass assignment, missing input validation, missing pagination, BOLA
   - GraphQL: query depth limiting, complexity analysis, introspection in production, resolver auth
   - WebSocket: connection auth, origin validation, message validation, message rate limiting
   - gRPC: TLS, auth interceptors, input validation, deadlines, reflection in production

4. **For large codebases (>200 source files):** Launch parallel Agent sub-tasks using the `security-scanner` agent:
   - Split the file list into batches of ~50 files
   - For each batch, invoke the Agent tool with:
     ```
     SCAN_TYPE: sast
     FILES: [comma-separated file paths in this batch]
     CHECKS: [relevant regex patterns for the project's languages, as name:pattern pairs]
     CONTEXT: language=<lang>, framework=<framework>, phase=sast
     ```
   - Launch all batch agents in parallel using multiple Agent tool calls in a single response
   - Collect results from all agents
   - **Deduplicate**: if the same file:line appears in multiple agent results, keep only one finding
   - Merge all unique findings into the main findings list

5. **Verify each match** — read 5-10 lines of surrounding context to confirm it's genuine:
   - Apply false positive rules from `skills/security-audit/references/false-positives.md`
   - Check if the match is in a comment, test file, or uses sanitized input
   - Check if a compensating control exists nearby (e.g., parameterized query on the next line)

6. Record findings with: file, line, severity, OWASP category, CWE, snippet, description, remediation.

---

## Phase 5 — IaC Review `[Phase 5/10]`

**Goal:** Audit Docker, Terraform, Kubernetes, CloudFormation, and CI/CD configurations.

**Reference:** Read `skills/security-audit/references/iac-security-checks.md` for detailed patterns.

**Steps:**

1. **Docker**: If `Dockerfile` or `docker-compose*.yml` exist:
   - Check for root user, secrets in build, unpinned images, privileged mode
   - Check for missing `.dockerignore`, exposed sensitive ports, missing healthcheck

2. **Terraform**: If `*.tf` files exist:
   - Check for public resources, hardcoded secrets, unencrypted storage
   - Check for overly permissive IAM, missing logging, state file security

3. **Kubernetes**: If K8s manifests exist:
   - Check for privileged containers, cluster-admin bindings, plaintext secrets
   - Check for missing security context, resource limits, network policies

4. **CI/CD**: Check pipeline configs:
   - GitHub Actions: secrets in config, unpinned actions, privileged execution
   - GitLab CI, Jenkins, etc.: similar patterns per reference

5. Record findings with severity, description, and remediation.

---

## Phase 6 — Secrets & Credentials `[Phase 6/10]`

**Goal:** Detect hardcoded secrets, API keys, tokens, and credentials.

**References:**
- Read `skills/security-audit/references/secrets-patterns.md` for 30+ regex patterns
- If `is_baas = true`: also check for BaaS-specific key exposure per `skills/security-audit/references/baas-security-checks.md`

**Steps:**

1. **File name scan**: Check for files that commonly contain secrets (`.env`, `credentials.json`, `*.pem`, `*.key`, etc.) that are tracked in git or not in `.gitignore`.

2. **Pattern matching**: Run Grep with each regex pattern category from the reference:
   - Cloud provider keys (AWS, GCP, Azure)
   - API keys & tokens (GitHub, Stripe, Slack, Twilio, SendGrid, etc.)
   - Database connection strings
   - Private keys
   - JWT tokens
   - Generic patterns (api_key, secret, password, token assignments)

3. **Apply exclusion rules**: Filter out false positives:
   - Test/fixture files (unless they contain real secrets)
   - Example/placeholder values
   - Documentation files
   - Lock files
   - Public keys and certificates
   - Empty/null assignments

4. **Git history scan** (if git repo): For the highest-risk patterns (AWS keys, private keys, Stripe live keys), check recent git history:
   ```
   git log -p --all -S '<pattern>' -- <relevant files>
   ```
   Flag secrets that were committed and removed — they may still be valid.

5. **BaaS key audit** (if `is_baas = true`):
   - **Supabase**: Check if `service_role` key is exposed in any `NEXT_PUBLIC_*`, `VITE_*`, or `REACT_APP_*` env var or in client-side code. Only the `anon` key should be public.
   - **Firebase**: Check if `firebase-admin` SDK or service account JSON is in client-accessible code.
   - **Check all `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*`** env vars — flag any that contain service keys, admin tokens, or database passwords.

6. Record findings with severity, the masked secret (show only first/last 4 chars), and remediation guidance.

---

## Phase 7 — Auth & Access Control `[Phase 7/10]`

**Goal:** Audit authentication, authorization, and access control — adapting to the platform type.

**References:**
- Read `skills/security-audit/references/auth-and-access-checks.md` for traditional auth patterns
- If `is_baas = true`: read `skills/security-audit/references/baas-security-checks.md` for RLS/security rules checks

**Steps:**

### For ALL platform types:

1. **JWT security**: If JWT is used:
   - Check for signature verification, algorithm restrictions
   - Check for weak secrets, missing expiration
   - Check token storage (localStorage vs httpOnly cookie)

2. **OAuth**: If OAuth/social auth is implemented:
   - Check for state parameter (CSRF)
   - Check for PKCE
   - Check redirect URI validation
   - Check token handling

### For traditional-server / fullstack-hybrid:

3. **Session management**:
   - Check for session regeneration on login
   - Check session store (not in-memory for production)
   - Check session timeout configuration
   - Check cookie security flags

4. **Password security**:
   - Check for proper hashing (bcrypt/argon2/scrypt)
   - Check password policy (minimum length, complexity)
   - Check for plaintext password storage

5. **RBAC**:
   - Check for authorization middleware on admin/privileged routes
   - Check for client-side only authorization
   - Check for horizontal privilege escalation (IDOR)
   - Check for mass assignment vulnerabilities

### For BaaS platforms (Supabase, Firebase, Appwrite, PocketBase):

6. **Row Level Security / Security Rules** (the most critical BaaS check):
   - **Supabase**: Check every table in `supabase/migrations/` has `ENABLE ROW LEVEL SECURITY`. Check that policies use `auth.uid()` for user-owned data. Flag `USING (true)` policies on non-public tables.
   - **Firebase Firestore**: Read `firestore.rules` — flag `allow read, write: if true` and rules without `request.auth != null`. Check for missing data validation in write rules.
   - **Firebase Realtime DB**: Read `database.rules.json` — flag `".read": true` and `".write": true`.
   - **Firebase Storage**: Read `storage.rules` — flag open access.
   - **Appwrite**: Check collection permissions for `Role.any()` on sensitive collections.
   - **PocketBase**: Check collection rules — flag empty rule strings (= public access).

7. **BaaS-specific auth**:
   - Check edge functions / Cloud Functions for auth verification
   - Check Realtime subscriptions for auth requirements
   - Check storage bucket access policies
   - Verify email confirmation is enabled
   - Check for App Check / captcha on auth endpoints

8. **Client-side authorization** (especially critical for BaaS):
   - Flag any role checks, admin checks, or permission checks that exist ONLY in frontend code
   - BaaS projects must enforce authorization through RLS policies / security rules, not UI logic
   - Check for direct database writes that modify sensitive fields (role, price, permissions) from client code

### For fullstack-hybrid (Next.js, Nuxt, SvelteKit):

9. **API route auth**:
   - Check every file in `pages/api/`, `app/api/`, `server/api/`, or `src/routes/+server` for auth verification
   - Flag API routes without `getServerSession`, `getUser`, `auth()`, or equivalent
   - Check middleware.ts/js for auth patterns

### For ALL platform types (continued):

10. **API authentication**:
    - Check for rate limiting on auth endpoints
    - Check API key handling (header vs. query string)
    - Check CSRF protection on state-changing endpoints

---

## Phase 8 — Logging & Monitoring `[Phase 8/10]`

**Goal:** Verify security event logging, detect log injection risks, and check for PII in logs.

**Reference:** Read `skills/security-audit/references/logging-monitoring-checks.md` for detailed patterns.

**Steps:**

1. **Security event logging**: Check if critical events are logged:
   - Authentication success/failure
   - Authorization failures
   - Admin operations
   - Data access/export

2. **Log injection**: Check for unsanitized user input in log statements. Check if structured (JSON) logging is used.

3. **PII in logs**: Search for logging statements that include passwords, tokens, emails, credit card numbers, or session IDs.

4. **Log configuration**:
   - Check for log rotation configuration
   - Check log transport security (TLS)
   - Check for correlation IDs in requests

5. **Monitoring**: Check for integration with monitoring/alerting platforms (Sentry, Datadog, New Relic, etc.).

---

## Phase 9 — Report & Remediation `[Phase 9/10]`

**Goal:** Compile findings, score severity, map compliance, auto-remediate, and generate markdown report.

**References:**
- Read `skills/security-audit/references/severity-scoring.md` for CVSS scoring and pre-scored findings
- Read `skills/security-audit/references/compliance-mapping.md` for CWE/OWASP/SOC2/PCI-DSS/HIPAA mapping
- Read `skills/security-audit/references/auto-remediation-patterns.md` for exact before/after fix patterns and safety guardrails

**Steps:**

### 9-pre. Cross-phase deduplication

Before scoring, deduplicate findings across all phases. The same vulnerability may be detected by multiple phases (e.g., CORS wildcard found by Phase 2 Config and Phase 4 SAST). Deduplication rules:

1. **Same file + same line** → keep only the finding from the most specific phase (e.g., Phase 7 Auth over Phase 4 SAST for an auth issue)
2. **Same vulnerability type + different files** → keep all (they're separate instances)
3. **Same concept at different specificity** → keep the more specific finding (e.g., "Missing RLS on users table" over "Missing authorization middleware")
4. **CORS/headers found in both Phase 2 and Phase 4** → keep the Phase 2 finding (that's the dedicated config phase); mark as already-covered in Phase 4

### 9a. Score and classify findings

1. For each finding, first check the **pre-scored findings table** in `severity-scoring.md`. If the finding matches a pre-scored entry, use that score directly.

2. For findings NOT in the pre-scored table, calculate using the simplified CVSS formula:
   ```
   Base Score = round((AV × AC × PR × UI) × max(C, I, A) × 10, 1)
   ```
   Assign each factor based on the finding's characteristics per the scoring rubric.

3. Apply **severity adjustments** from `false-positives.md`:
   - Escalate: if finding is in auth/payment path, or chains with another finding
   - Reduce: if in test code, dev-only config, or has compensating controls

4. Map each finding to compliance frameworks using the **Quick Reference table** in `compliance-mapping.md`. For each finding, record: CWE, OWASP category, and which SOC 2 / PCI-DSS / HIPAA requirements it violates.

5. Sort findings by severity (Critical first), then by CVSS score within each level.

### 9b. Auto-remediate

**Before auto-fixing, read `skills/security-audit/references/auto-remediation-patterns.md`** for exact code transforms and safety rules.

**Safety checks before any auto-fix:**
1. Read 20 lines of surrounding context to understand the code structure
2. Detect code style (indentation, quotes, semicolons) by reading nearby code
3. Verify the fix won't exceed 15 lines of changes
4. If the project has uncommitted git changes, warn the user before modifying files
5. After applying a fix, re-read the modified file to verify syntactic validity

**Auto-fix Low/Medium findings silently** (apply immediately, use the exact patterns from the auto-remediation reference):
- Add missing security headers middleware (helmet for Express, secure settings for Django, etc.)
- Add `.gitignore` entries for `.env`, `*.pem`, `*.key`, `credentials.json`
- Fix cookie security flags (`secure: true`, `httpOnly: true`, `sameSite: 'lax'`)
- Add missing `X-Content-Type-Options`, `X-Frame-Options` headers
- Fix `SameSite` cookie attribute
- Pin Docker base image tags (replace `latest` with current version)
- Add `.dockerignore` if missing
- Remove `console.log` statements containing sensitive data
- Add `Referrer-Policy` header

**Auto-fix High/Critical with user confirmation** (ask before applying, show the exact before/after diff):
- Parameterize SQL queries (replace string concatenation with prepared statements)
- Replace `eval()` / `exec()` with safe alternatives
- Add authentication middleware to unprotected routes
- Replace `innerHTML` with `textContent` (or add DOMPurify if HTML rendering is intentional)
- Fix JWT verification (add algorithm whitelist, enable signature verification)
- Replace `pickle.load` with `json.load` or `yaml.safe_load`
- Remove hardcoded secrets and replace with environment variable references
- Add CSRF protection middleware
- Fix command injection (replace `exec` with `execFile`, remove `shell=True`)
- Fix disabled TLS certificate verification

**Never auto-fix** (flag as manual remediation only):
- Architecture-level auth changes requiring multi-file refactoring
- Database schema changes
- Third-party API key rotation
- Anything requiring changes across 3+ files
- Production configuration changes that risk downtime

For each auto-fix:
- Show the before/after diff using the box-drawing card style
- Record in the report as "Auto-Remediated"

### 9c. Generate markdown report

Read the report template from `skills/security-audit/assets/report-template.md` and fill in all sections:

1. **Executive Summary**: Overall risk rating, total findings by severity, stack summary, top 3 critical findings
2. **Phase Results**: Status icon and finding count for each phase
3. **Findings by Severity**: Each finding as a box-drawing card with file:line, CWE, CVSS score, snippet, description, remediation, and status (auto-fixed / manual)
4. **Compliance Mapping**: Table mapping each finding to CWE/OWASP/SOC2/PCI-DSS/HIPAA
5. **Remediation Summary**: What was auto-fixed vs. what needs manual attention, with follow-up actions
6. **Dependency Audit**: Summary of CVE findings from Phase 3
7. **Secrets Scan**: Summary with masked values from Phase 6
8. **IaC Review**: Summary of infrastructure findings from Phase 5
9. **Re-audit Instructions**: How to verify fixes

Write the completed report to `SECURITY-AUDIT-REPORT.md` in the project root. If the file already exists, overwrite it (it's a generated artifact).

---

## Phase 10 — PDF Report Generation `[Phase 10/10]`

**Goal:** Generate a professionally styled PDF (or HTML fallback) of the security audit report for sharing, archiving, and compliance documentation.

**Reference:** Read `skills/security-audit/references/pdf-report-guide.md` for generation strategies, CSS styling, and fallback methods.

**Steps:**

### 10a. Detect available PDF tooling

Try each method in priority order. Use the first one that succeeds:

1. **Puppeteer/Playwright** — check: `npx puppeteer --version 2>/dev/null || npx playwright --version 2>/dev/null`
2. **pandoc + wkhtmltopdf** — check: `pandoc --version 2>/dev/null && wkhtmltopdf --version 2>/dev/null`
3. **pandoc + LaTeX** — check: `pandoc --version 2>/dev/null && xelatex --version 2>/dev/null`
4. **Python pdfkit/weasyprint** — check: `python3 -c "import pdfkit" 2>/dev/null || python3 -c "import weasyprint" 2>/dev/null`
5. **HTML fallback** — always available (no external tools needed)

### 10b. Convert markdown to styled HTML

1. Read `SECURITY-AUDIT-REPORT.md` (generated in Phase 9)
2. Convert to HTML with the full CSS from the PDF reference file
3. Apply the visual styling:
   - Cover page with project name, date, scope, risk rating, and "CONFIDENTIAL" banner
   - Dashboard with severity counts and visual progress bars
   - Finding cards with colored severity badges
   - Code blocks with dark background and monospace font
   - Tables with alternating row colors
   - Proper page breaks (before Critical section, avoid breaks mid-finding)
   - Header: "Security Audit Report — Confidential"
   - Footer: "Page X of Y"

### 10c. Generate PDF

Using the detected method from 10a, convert the styled HTML to PDF with these settings:
- **Format:** A4
- **Margins:** top 20mm, right 15mm, bottom 20mm, left 15mm
- **Background:** print background colors (for severity badges, dashboard, code blocks)
- **Output:** `SECURITY-AUDIT-REPORT.pdf` in the project root

### 10d. Fallback to HTML

If NO PDF tool is available:
1. Write `SECURITY-AUDIT-REPORT.html` to the project root — a self-contained HTML file with all CSS embedded inline
2. Output instructions to the user:
   ```
   📄 No PDF tool detected. HTML report generated instead.
   Open SECURITY-AUDIT-REPORT.html in your browser → Print (Ctrl+P) → Save as PDF
   ```

### 10e. Output summary

Display the generated files:
```
╔══════════════════════════════════════════════════════════════╗
║  📁 REPORT FILES GENERATED                                  ║
╠══════════════════════════════════════════════════════════════╣
║  📝 SECURITY-AUDIT-REPORT.md   ·········· Markdown report   ║
║  📄 SECURITY-AUDIT-REPORT.pdf  ·········· PDF report         ║
║  (or .html if PDF tools not available)                      ║
╚══════════════════════════════════════════════════════════════╝
```

---

### Final summary (after all phases)

Output a formatted summary to the user showing:
- Total findings by severity
- Auto-remediations applied
- Top 3 most critical findings requiring attention
- Overall risk rating
- Files generated (markdown + PDF/HTML)
- Instruction to run `/security-audit recheck` after fixing remaining issues

---

## Rules

1. **Be thorough but minimize false positives.** Always apply `false-positives.md` rules. Verify matches by reading 5-10 lines of surrounding code. Don't flag test fixtures, mocked data, or commented-out code.
2. **Respect the codebase.** Auto-fixes must match the project's code style (indentation, quotes, semicolons). Read nearby code to infer style before editing. Follow the safety guardrails in `auto-remediation-patterns.md`.
3. **Never break functionality.** If unsure whether a fix is safe, ask the user instead of applying it. Never auto-fix across 3+ files. Re-read modified files after fixing to verify syntax.
4. **Progressive loading.** Only read reference files when their phase is about to run. This keeps context lean.
5. **Parallel scanning.** For large codebases (>200 files), use the security-scanner agent to parallelize. Split into batches of ~50 files. Deduplicate findings across batches.
6. **Graceful degradation.** If a CLI tool (npm audit, pip-audit, etc.) isn't installed, fall back to Grep-based analysis. If no PDF tool is available, generate HTML. Never fail because a tool is missing.
7. **Mask secrets.** Never output full secrets, keys, or passwords. Show only the first 4 and last 4 characters.
8. **Recheck mode.** When rechecking, only verify the specific findings from the prior report. Don't run a full scan.
9. **Use the STACK_PROFILE.** Skip irrelevant checks — don't run Python patterns on JavaScript projects, don't check GraphQL if no GraphQL is detected, etc.
10. **Generate all report formats.** Always produce the markdown report. Always attempt PDF generation. Fall back to HTML if no PDF tooling is available.
