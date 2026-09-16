# Target names match Appendix A exactly, because that is the checklist every
# new joiner works through. If a name here drifts from the handbook, someone
# runs a command that does not exist on their first morning.
#
# Every Python command below runs through .venv explicitly. That means you do
# NOT have to remember to activate anything, and a stray Anaconda or system
# Python cannot silently be used instead.

VENV   := .venv
PY     := $(VENV)/bin/python
PIP    := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest
RUFF   := $(VENV)/bin/ruff

.PHONY: help setup check-venv preflight dev down clean logs ps urls migrate seed test smoke lint fmt jwt fga-explain demo-week1 demo-reset

help:                    ## Show this list
	@grep -E '^[a-z0-9-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup:                   ## One-time: build the virtual environment and install tools
	@if command -v python3.12 >/dev/null 2>&1; then \
	  BASE=python3.12; \
	elif command -v python3.13 >/dev/null 2>&1; then \
	  BASE=python3.13; \
	else \
	  BASE=python3; \
	  echo ""; \
	  echo "  WARNING: python3.12 not found, falling back to $$(python3 --version)."; \
	  echo "  CI runs 3.12. Anything from 3.11 up works:  brew install python@3.12"; \
	  echo ""; \
	fi; \
	BASE=$$($$BASE -c 'import sys; print(getattr(sys, "_base_executable", sys.executable))'); \
	$$BASE -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { \
	  echo ""; \
	  echo "  $$BASE is $$($$BASE --version). Gatekeep needs Python 3.11 or newer."; \
	  echo "  If a virtual environment is active, run 'deactivate' and try again."; \
	  echo "  Otherwise:  brew install python@3.12"; \
	  echo ""; \
	  exit 1; }; \
	echo "Using  $$BASE ($$($$BASE --version))"; \
	rm -rf $(VENV); \
	$$BASE -m venv $(VENV)
	@$(PIP) install -q --upgrade pip
	@$(PIP) install -q -r requirements-dev.txt
	@for r in services/*/requirements.txt; do \
	  $(PIP) install -q -r "$$r" || exit 1; \
	done
	@echo "Ready:  $$($(PY) --version)"
	@echo "You do NOT need to activate anything. Just run 'make smoke'."

check-venv:
	@test -x $(PY) || { \
	  echo ""; \
	  echo "  No virtual environment yet."; \
	  echo "  Run:  make setup"; \
	  echo ""; \
	  exit 1; }

preflight:
	@test -f deploy/keycloak-realm.json || { \
	  echo ""; \
	  echo "  deploy/keycloak-realm.json is missing, or is a DIRECTORY."; \
	  echo ""; \
	  echo "  Docker creates an empty folder when told to mount a file that is"; \
	  echo "  not there. Keycloak then imports nothing, logs 'Import finished"; \
	  echo "  successfully', and passes its health check with no realm at all."; \
	  echo ""; \
	  echo "  Fix:  docker compose down"; \
	  echo "        rmdir deploy/keycloak-realm.json     # if it is a folder"; \
	  echo "        git checkout deploy/keycloak-realm.json"; \
	  echo "        make dev"; \
	  echo ""; \
	  exit 1; }
	@python3 -c "import json,sys; d=json.load(open('deploy/keycloak-realm.json')); \
	  sys.exit(0 if d.get('realm')=='gatekeep' and len(d.get('users',[]))>=3 else 1)" 2>/dev/null || { \
	  echo ""; \
	  echo "  deploy/keycloak-realm.json is not valid JSON, or is not the"; \
	  echo "  gatekeep realm with its three seeded users."; \
	  echo ""; \
	  exit 1; }

dev: preflight                     ## Start everything and wait until it is genuinely ready
	docker compose up -d
	@echo "Waiting for services (Keycloak takes 30-60s on a cold start)..."
	@for i in $$(seq 1 60); do \
	  bad=$$(docker compose ps --format '{{.Name}} {{.Health}}' | grep -cv ' healthy$$' || true); \
	  if [ "$$bad" -eq 0 ]; then echo "\nAll healthy."; docker compose ps; exit 0; fi; \
	  printf "."; sleep 5; \
	done; \
	echo "\nSomething did not come up. Try: make logs"; docker compose ps; exit 1

down:                    ## Stop everything, keep the database
	docker compose down

clean:                   ## Stop everything and wipe the database too
	docker compose down -v

logs:                    ## Follow the logs
	docker compose logs -f --tail=50

ps:                      ## What is running
	docker compose ps

migrate: check-venv      ## Apply database schema (raw SQL, in order)
	$(PY) services/control-plane/migrations/apply.py

seed: check-venv         ## Load the policy model, tuples and demo data
	$(PY) deploy/seed/seed.py

jwt: check-venv          ## Appendix A: look inside a token
	$(PY) exercises/jwt_exercise.py

test: check-venv         ## Run the test suite
	$(PYTEST) tests/ -v

smoke: check-venv        ## Just the 'is my machine working' check
	$(PYTEST) tests/test_stack_smoke.py -v

lint: check-venv         ## Style and error checks, same as CI runs
	$(RUFF) format --check .
	$(RUFF) check .

fmt: check-venv          ## Fix formatting automatically
	$(RUFF) format .
	$(RUFF) check --fix .

fga-explain: check-venv  ## Ask the policy engine a question and see why it answered
	@$(PY) tools/fga_explain.py

demo-week1: check-venv   ## Week 1 demo: identity, per-record policy, tamper-evident log
	@$(PY) tools/week1_demo.py $(if $(PAUSE),--pause,)

services: check-venv      ## Run control plane, token service, PEP and mock Salesforce (Ctrl+C stops)
	@$(PY) tools/run_services.py

demo: check-venv         ## The full narrative, explained step by step  (PAUSE=1 to stop between steps, BRIEF=1 for the timed run)
	@$(PY) tools/demo.py $(if $(PAUSE),--pause,) $(if $(BRIEF),--brief,)

demo-reset: check-venv   ## Back to a clean demo state: empty tables, fresh seed, reset mock Salesforce
	@$(PY) tools/demo_reset.py

audit-verify: check-venv ## Walk the audit chain and name the first broken entry
	@$(PY) tools/audit_verify.py

gk: check-venv           ## Console stand-in: make gk ARGS="pending --as priya"
	@$(PY) tools/gk.py $(ARGS)

urls:                    ## Where everything lives
	@echo "Keycloak admin      http://localhost:8080          (admin / admin)"
	@echo "Realm discovery     http://localhost:8080/realms/gatekeep/.well-known/openid-configuration"
	@echo "OpenFGA API         http://localhost:8081"
	@echo "Policy explainer    make fga-explain      (replaces the playground)"
	@echo "OpenBao             http://localhost:8200          (token: root)"
	@echo "Postgres            postgres://gatekeep:gatekeep@localhost:5432/gatekeep"
	@echo ""
	@echo "Control plane       http://localhost:8000/docs    (make services)"
	@echo "Token service       http://localhost:8001/docs    JWKS at /.well-known/jwks.json"
	@echo "PEP proxy           http://localhost:8002/proxy/salesforce/..."
	@echo "Mock Salesforce     http://localhost:8003         (answers only the PEP)"
	@echo ""
	@echo "Test logins: priya@acme.test / priya   (analyst)"
	@echo "             admin@acme.test / admin   (security admin)"
	@echo "             auditor@acme.test / auditor (read-only)"
