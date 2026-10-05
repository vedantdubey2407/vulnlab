# SecuScan – Automated Web Security Testing Platform

SecuScan is a small security-learning lab I built to understand what happens when **static analysis, dynamic testing, and CI/CD security checks** are connected together.

The application is intentionally vulnerable. It is designed to run locally with fake data so I can break it, scan it, understand the finding, and then fix the vulnerable code.

> **Safety:** Run this project only on localhost or an isolated lab network. Do not deploy the vulnerable app to the public internet or point the included scanners at systems you do not own or have permission to test.

## What is included?

```text
secuscan/
├── app/
│   ├── main.py
│   ├── requirements.txt
│   └── VULNERABILITIES.md
├── semgrep-rules/
│   ├── sqli.yaml
│   ├── weak-jwt.yaml
│   └── idor.yaml
├── nuclei-templates/
│   ├── sqli.yaml
│   ├── weak-jwt.yaml
│   └── idor.yaml
├── .github/workflows/
│   └── security-scan.yml
├── THREAT_MODEL.md
└── README.md
```

## The three intentional flaws

1. **SQL injection** – `/search?q=...` builds SQL with string interpolation.
2. **Broken authentication / weak JWT** – `/login` uses the intentionally weak shared password `password123`, a hardcoded JWT secret, and no token expiry claim.
3. **IDOR** – `/users/{user_id}/profile` returns the requested user's record without checking whether the caller is allowed to view that user.

The exact locations are documented in `app/VULNERABILITIES.md`.

## Run the vulnerable application

From the repository root:

```bash
cd app
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```powershell
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux**

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
uvicorn main:app --reload --port 8000
```

Open the API docs at `http://127.0.0.1:8000/docs`.

## Try the vulnerabilities manually

### 1. SQL injection

Normal search:

```text
http://127.0.0.1:8000/search?q=alice
```

Lab payload:

```text
http://127.0.0.1:8000/search?q=' OR 1=1 -- 
```

The vulnerable query can return all seeded users instead of only users matching the intended search.

### 2. Weak authentication / JWT

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

The response contains a bearer token. The implementation deliberately uses the shared weak password and a hardcoded signing secret, and the JWT has no `exp` claim.

### 3. IDOR

No authentication is required for this intentionally vulnerable endpoint:

```text
http://127.0.0.1:8000/users/2/profile
```

It returns Bob's profile even though the caller has not demonstrated that they are Bob or are authorized to view Bob's data.

## Run Semgrep

Install Semgrep:

```bash
python -m pip install semgrep
```

Run all three custom rules:

```bash
semgrep scan --config semgrep-rules app
```

The rules are deliberately small and readable. They are meant to teach the connection between a source-code pattern and a security finding, not to be a production-grade security ruleset.

## Run Nuclei

Install Nuclei using the official ProjectDiscovery installation method for your operating system, then run:

```bash
nuclei -u http://127.0.0.1:8000 -t nuclei-templates -severity high,critical
```

The templates actually send requests to the local application:

- `sqli.yaml` injects a condition into `/search` and looks for multiple seeded records.
- `idor.yaml` requests another user's profile without authorization and checks for Bob's fake email.
- `weak-jwt.yaml` performs the intentionally weak login and then confirms that the returned bearer token grants access to the profile endpoint.

## Dependency and secret checks

Run dependency auditing:

```bash
pip-audit -r app/requirements.txt
```

Run gitleaks using your installed gitleaks binary:

```bash
gitleaks detect --source . --redact
```

## CI/CD

`.github/workflows/security-scan.yml` runs on pushes and pull requests. It:

1. installs the application dependencies,
2. runs the custom Semgrep rules,
3. starts the FastAPI lab,
4. runs the custom Nuclei templates,
5. runs `pip-audit`,
6. runs gitleaks, and
7. uploads scan logs/results as workflow artifacts.

The security scanners are configured so high/critical findings make the workflow fail. Because this repository intentionally contains vulnerable code, a clean CI run is **not** the goal; the interesting part is seeing the pipeline catch the known flaws.

## Threat model

`THREAT_MODEL.md` maps the application to STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.

## What I learned

The main lesson is that no single scanner gives the full picture.

- **Static analysis** can spot dangerous coding patterns before the application runs.
- **Dynamic analysis** checks what the application actually does when it receives malicious input.
- **Dependency scanning** catches problems in third-party packages that my own code might not reveal.
- **Secret scanning** helps prevent credentials from accidentally entering Git history.
- **Threat modeling** gives the findings a bigger security context instead of treating scanner output as a random list of warnings.

The next useful exercise is to create a `fixed/` version of the app and make each scanner finding disappear one by one: parameterize SQL, use a strong secret with short-lived JWTs, and enforce object-level authorization.
