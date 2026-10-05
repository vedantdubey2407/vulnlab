# SecuScan STRIDE Threat Model

## Scope

The target is the intentionally vulnerable FastAPI application in `app/main.py`. The lab assumes fake data and localhost/isolated execution.

| STRIDE category | Relevant risk? | Mapping | Detection |
|---|---|---|---|
| **Spoofing** | Yes | Weak JWT signing secret and weak login password can let an attacker obtain or forge an identity token. | Semgrep: `secuscan-weak-jwt-hardcoded-secret`; Nuclei: `secuscan-weak-jwt` |
| **Tampering** | Yes, indirectly | A forged JWT could be used to act as another user if authorization decisions trusted token claims. | Semgrep: `secuscan-weak-jwt-hardcoded-secret`; Nuclei: `secuscan-weak-jwt` |
| **Repudiation** | Yes, as a design concern | The demo has no meaningful audit trail for authentication or profile access, so actions cannot be strongly attributed. The three requested scanner rules do not directly detect missing audit logging. | Not directly covered by the requested Semgrep/Nuclei rules |
| **Information Disclosure** | Yes | SQL injection can expose database records; IDOR exposes another user's profile. | Semgrep: `secuscan-python-sqli-string-interpolation`, `secuscan-fastapi-profile-idor`; Nuclei: `secuscan-sqli`, `secuscan-idor` |
| **Denial of Service** | No direct requested finding | No intentional DoS primitive is included. | None |
| **Elevation of Privilege** | Yes | Weak authentication and missing object ownership checks can let a low-privileged user access resources belonging to another identity. | Semgrep: `secuscan-weak-jwt-hardcoded-secret`, `secuscan-fastapi-profile-idor`; Nuclei: `secuscan-weak-jwt`, `secuscan-idor` |

## Trust boundaries

1. **HTTP client → FastAPI**: all request parameters are untrusted.
2. **FastAPI → SQLite**: SQL must be treated as a code/data boundary; parameterization is required in a real application.
3. **FastAPI → JWT validation**: signing keys and claims are security-sensitive inputs.
4. **Authenticated user → object access**: authentication alone is not authorization; the requested object must be checked against the user's permissions.

## Important limitation

This is a learning lab, so the detection rules intentionally target recognizable patterns. Real security tooling should reduce false positives with data-flow analysis, framework-aware models, authentication context, and application-specific tests.
