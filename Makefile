.PHONY: run semgrep nuclei audit secrets

run:
	uvicorn app.main:app --reload --port 8000

semgrep:
	semgrep scan --config semgrep-rules app

nuclei:
	nuclei -u http://127.0.0.1:8000 -t nuclei-templates -severity high,critical

audit:
	pip-audit -r app/requirements.txt

secrets:
	gitleaks detect --source . --redact
