# Compliance Mapping Reference

Reference file for Phase 9 (Report & Remediation). Maps security findings to CWE, OWASP Top 10, SOC 2, HIPAA, and PCI-DSS frameworks.

---

## CWE (Common Weakness Enumeration) Mapping

### Injection

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| SQL Injection | CWE-89 | A03 | Improper neutralization of SQL commands |
| NoSQL Injection | CWE-943 | A03 | Improper neutralization of NoSQL queries |
| Command Injection | CWE-78 | A03 | Improper neutralization of OS commands |
| XSS (Reflected) | CWE-79 | A03 | Improper neutralization of script in web page |
| XSS (Stored) | CWE-79 | A03 | Improper neutralization of stored script |
| LDAP Injection | CWE-90 | A03 | Improper neutralization of LDAP queries |
| XPath Injection | CWE-643 | A03 | Improper neutralization of XPath expressions |
| Template Injection | CWE-1336 | A03 | Improper neutralization of template expressions |
| Log Injection | CWE-117 | A09 | Improper output neutralization for logs |
| Code Injection (eval) | CWE-94 | A03 | Improper control of code generation |

### Authentication & Access

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| Broken Authentication | CWE-287 | A07 | Improper authentication |
| Session Fixation | CWE-384 | A07 | Session fixation |
| Missing Authorization | CWE-862 | A01 | Missing authorization |
| Incorrect Authorization | CWE-863 | A01 | Incorrect authorization |
| IDOR | CWE-639 | A01 | Authorization bypass through user-controlled key |
| CSRF | CWE-352 | A01 | Cross-site request forgery |
| Privilege Escalation | CWE-269 | A01 | Improper privilege management |
| Mass Assignment | CWE-915 | A04 | Improperly controlled modification of object attributes |
| Default Credentials | CWE-1392 | A07 | Use of default credentials |
| Weak Password | CWE-521 | A07 | Weak password requirements |

### Cryptography

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| Weak Hashing | CWE-328 | A02 | Use of weak hash |
| Weak Encryption | CWE-327 | A02 | Use of broken crypto algorithm |
| Hardcoded Credentials | CWE-798 | A02 | Use of hardcoded credentials |
| Hardcoded Crypto Key | CWE-321 | A02 | Use of hardcoded cryptographic key |
| Insufficient Key Size | CWE-326 | A02 | Inadequate encryption strength |
| Missing Encryption (transit) | CWE-319 | A02 | Cleartext transmission of sensitive info |
| Missing Encryption (rest) | CWE-311 | A02 | Missing encryption of sensitive data |

### Data Exposure

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| Sensitive Data in Logs | CWE-532 | A09 | Insertion of sensitive info into log file |
| Error Message Info Leak | CWE-209 | A04 | Error message information exposure |
| Path Traversal | CWE-22 | A01 | Path traversal |
| SSRF | CWE-918 | A10 | Server-side request forgery |
| Open Redirect | CWE-601 | A01 | URL redirection to untrusted site |
| Directory Listing | CWE-548 | A05 | Exposure of info through directory listing |

### Configuration

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| Security Misconfiguration | CWE-16 | A05 | Configuration |
| Debug Mode | CWE-489 | A05 | Active debug code |
| XXE | CWE-611 | A05 | Improper restriction of XML external entity |
| Missing Security Headers | CWE-693 | A05 | Protection mechanism failure |
| CORS Misconfiguration | CWE-942 | A05 | Permissive cross-domain policy |
| Cookie Without Flags | CWE-614 | A05 | Cookie without Secure flag |

### Supply Chain

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| Vulnerable Component | CWE-1035 | A06 | Vulnerable third-party component |
| Unsafe Deserialization | CWE-502 | A08 | Deserialization of untrusted data |
| Missing SRI | CWE-829 | A08 | Inclusion of functionality from untrusted control sphere |
| Missing Lockfile | CWE-1357 | A08 | Reliance on insufficiently trustworthy component |

### Monitoring

| Vulnerability | CWE | OWASP | Description |
|---|---|---|---|
| Insufficient Logging | CWE-778 | A09 | Insufficient logging |
| Missing Auth Event Logging | CWE-223 | A09 | Omission of security-relevant information |

---

## SOC 2 Trust Service Criteria Mapping

### CC6 — Logical and Physical Access Controls

| SOC 2 Criteria | Related Findings |
|---|---|
| CC6.1 — Logical access security | Missing authentication, weak auth, default creds |
| CC6.2 — User provisioning | Mass assignment, privilege escalation, missing RBAC |
| CC6.3 — Registration and authorization | Missing authorization middleware, IDOR |
| CC6.6 — System boundaries | CORS misconfiguration, missing network policies, public resources |
| CC6.7 — Restrict data movement | SSRF, path traversal, data exfiltration vectors |
| CC6.8 — Prevent unauthorized software | Dependency confusion, unpinned dependencies |

### CC7 — System Operations

| SOC 2 Criteria | Related Findings |
|---|---|
| CC7.1 — Detect changes | Missing monitoring, insufficient logging |
| CC7.2 — Monitor system components | Missing security event logging, no alerting |
| CC7.3 — Evaluate security events | Missing audit trail, no log analysis |
| CC7.4 — Respond to incidents | No incident response indicators in code/config |

### CC8 — Change Management

| SOC 2 Criteria | Related Findings |
|---|---|
| CC8.1 — Authorize changes | Missing branch protection, no PR requirements |
| CC8.2 — Test changes | Missing security tests, no CI security checks |

### CC9 — Risk Mitigation

| SOC 2 Criteria | Related Findings |
|---|---|
| CC9.2 — Identify and assess risks | No security scanning in CI/CD, vulnerable components |

---

## PCI-DSS v4.0 Mapping

### Requirement 2 — Secure Configurations

| PCI-DSS Req | Related Findings |
|---|---|
| 2.2.1 — System hardening | Debug mode, default configs, unnecessary services |
| 2.2.7 — Encrypted non-console admin | Missing TLS, weak TLS versions |

### Requirement 3 — Protect Stored Account Data

| PCI-DSS Req | Related Findings |
|---|---|
| 3.1.1 — Data retention | PII in logs without retention policy |
| 3.4.1 — Render PAN unreadable | Credit card data in logs, unencrypted storage |
| 3.5.1 — Protect encryption keys | Hardcoded keys, keys in source code |

### Requirement 4 — Protect Data in Transit

| PCI-DSS Req | Related Findings |
|---|---|
| 4.2.1 — Strong cryptography in transit | Missing TLS, weak ciphers, disabled cert verification |
| 4.2.2 — Secure end-user messaging | Tokens in URLs, insecure cookies |

### Requirement 6 — Secure Software

| PCI-DSS Req | Related Findings |
|---|---|
| 6.2.1 — Secure development | All SAST findings (injection, XSS, etc.) |
| 6.2.2 — Security in SDLC | Missing security testing in CI |
| 6.2.4 — Software attack prevention | Input validation, output encoding |
| 6.3.1 — Identify vulnerabilities | Vulnerable dependencies, missing patches |
| 6.3.2 — Keep software up to date | Outdated components, unpinned versions |
| 6.4.1 — Attack detection for web apps | Missing WAF, CSP, security headers |
| 6.4.3 — Manage payment page scripts | Missing SRI, CSP for payment pages |

### Requirement 7 — Restrict Access

| PCI-DSS Req | Related Findings |
|---|---|
| 7.2.1 — Access control model | Missing RBAC, overly permissive roles |
| 7.2.2 — Assign access based on need | Overly broad IAM policies, wildcards |

### Requirement 8 — Identify Users

| PCI-DSS Req | Related Findings |
|---|---|
| 8.2.1 — Unique user IDs | Shared credentials, default accounts |
| 8.3.1 — Authenticate all users | Missing authentication, public endpoints |
| 8.3.4 — Invalid auth attempt lockout | Missing account lockout, no rate limiting |
| 8.3.6 — Password complexity | Weak password policy |
| 8.3.9 — Password change requirements | No password rotation enforcement |
| 8.4.2 — MFA for remote access | No MFA implementation |

### Requirement 10 — Log and Monitor

| PCI-DSS Req | Related Findings |
|---|---|
| 10.2.1 — Audit log coverage | Missing security event logging |
| 10.2.2 — Log auth events | Missing auth logging |
| 10.3.1 — Protect audit logs | Logs without integrity protection |
| 10.4.1 — Review audit logs | Missing log analysis/alerting |
| 10.5.1 — Retain audit logs | Insufficient log retention |

### Requirement 11 — Test Security

| PCI-DSS Req | Related Findings |
|---|---|
| 11.3.1 — Vulnerability scanning | Vulnerable components, missing scanning |
| 11.4.1 — Intrusion detection | Missing monitoring, no alerting |

---

## HIPAA Security Rule Mapping

### Technical Safeguards (§164.312)

| HIPAA Requirement | Related Findings |
|---|---|
| §164.312(a)(1) — Access control | Missing auth, broken access control, IDOR |
| §164.312(a)(2)(i) — Unique user ID | Default credentials, shared accounts |
| §164.312(a)(2)(iii) — Auto logoff | Missing session timeout |
| §164.312(a)(2)(iv) — Encryption at rest | Missing encryption, unencrypted storage |
| §164.312(b) — Audit controls | Insufficient logging, missing audit trail |
| §164.312(c)(1) — Integrity | Missing integrity checks, CSRF, mass assignment |
| §164.312(d) — Person authentication | Weak auth, missing MFA |
| §164.312(e)(1) — Transmission security | Missing TLS, weak ciphers |
| §164.312(e)(2)(ii) — Encryption in transit | Disabled cert verification, cleartext transport |

### Administrative Safeguards (§164.308)

| HIPAA Requirement | Related Findings |
|---|---|
| §164.308(a)(1)(ii)(D) — Info system review | Missing monitoring, no security scanning |
| §164.308(a)(5)(ii)(B) — Protection from malicious software | Vulnerable dependencies, no SRI |
| §164.308(a)(5)(ii)(C) — Log-in monitoring | Missing auth event logging |
| §164.308(a)(5)(ii)(D) — Password management | Weak password policy, missing complexity |

---

## Quick Reference: Finding → Compliance

Use this table when generating the compliance mapping section of the report:

| Finding Type | CWE | OWASP | SOC 2 | PCI-DSS | HIPAA |
|---|---|---|---|---|---|
| SQL Injection | 89 | A03 | CC6.1 | 6.2.1 | §164.312(a)(1) |
| XSS | 79 | A03 | CC6.1 | 6.2.4 | §164.312(a)(1) |
| Command Injection | 78 | A03 | CC6.1 | 6.2.1 | §164.312(a)(1) |
| Missing Auth | 862 | A01 | CC6.1 | 8.3.1 | §164.312(a)(1) |
| Broken Auth | 287 | A07 | CC6.1 | 8.3.1 | §164.312(d) |
| IDOR | 639 | A01 | CC6.3 | 7.2.1 | §164.312(a)(1) |
| CSRF | 352 | A01 | CC6.1 | 6.2.4 | §164.312(c)(1) |
| SSRF | 918 | A10 | CC6.7 | 6.2.1 | §164.312(a)(1) |
| Path Traversal | 22 | A01 | CC6.7 | 6.2.1 | §164.312(a)(1) |
| Hardcoded Secrets | 798 | A02 | CC6.1 | 3.5.1 | §164.312(a)(1) |
| Weak Crypto | 327 | A02 | CC6.1 | 4.2.1 | §164.312(e)(1) |
| Weak Password Hash | 328 | A02 | CC6.1 | 8.3.6 | §164.312(d) |
| Missing TLS | 319 | A02 | CC6.6 | 4.2.1 | §164.312(e)(1) |
| Debug Mode | 489 | A05 | CC6.1 | 2.2.1 | §164.312(a)(1) |
| Missing Headers | 693 | A05 | CC6.6 | 6.4.1 | §164.312(a)(1) |
| CORS Misconfig | 942 | A05 | CC6.6 | 6.4.1 | §164.312(a)(1) |
| Insecure Cookie | 614 | A05 | CC6.1 | 4.2.2 | §164.312(e)(1) |
| Vulnerable Deps | 1035 | A06 | CC6.8 | 6.3.1 | §164.308(a)(5) |
| Deserialization | 502 | A08 | CC6.1 | 6.2.1 | §164.312(a)(1) |
| Missing Logging | 778 | A09 | CC7.2 | 10.2.1 | §164.312(b) |
| PII in Logs | 532 | A09 | CC7.1 | 3.4.1 | §164.312(b) |
| Default Creds | 1392 | A07 | CC6.1 | 8.2.1 | §164.312(a)(2)(i) |
| Missing MFA | — | A07 | CC6.1 | 8.4.2 | §164.312(d) |
| Session Issues | 384 | A07 | CC6.1 | 8.3.1 | §164.312(d) |
| XXE | 611 | A05 | CC6.1 | 6.2.1 | §164.312(a)(1) |
| Missing Rate Limit | — | A04 | CC6.1 | 8.3.4 | §164.312(a)(1) |
| Privilege Escalation | 269 | A01 | CC6.2 | 7.2.1 | §164.312(a)(1) |
