# Intentional Vulnerabilities

This file documents flaws that are **deliberately** present in `app/main.py`. Do not copy these patterns into production software.

| ID | Vulnerability | Location | Intentional flaw |
|---|---|---|---|
| SECUSCAN-SQLI | SQL Injection | `main.py` `/search` handler | User-controlled `q` is interpolated into a SQL statement with an f-string and executed directly. |
| SECUSCAN-JWT | Broken Authentication / Weak JWT | `main.py` `JWT_SECRET`, `/login` | JWT signing uses hardcoded secret `secret`; tokens have no `exp` claim; the lab also accepts the shared weak password `password123`. |
| SECUSCAN-IDOR | Insecure Direct Object Reference | `main.py` `/users/{user_id}/profile` | The endpoint fetches whichever `user_id` is supplied and never verifies that the authenticated subject owns or may view that record. |

## Safe lab assumptions

- The database contains fake users only.
- The application is intended for localhost/isolated practice.
- The vulnerabilities are intentionally introduced so the scanners have something concrete to find.
