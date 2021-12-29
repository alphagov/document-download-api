SHELL := /bin/bash

CF_API ?= api.cloud.service.gov.uk
NOTIFY_CREDENTIALS ?= ~/.notify-credentials

CF_APP = document-download-api
CF_MANIFEST_PATH ?= /tmp/manifest.yml


## DEVELOPMENT

.PHONY: help
help:
	@cat $(MAKEFILE_LIST) | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: bootstrap
bootstrap: ## install app dependencies
	pip install -r requirements_for_test.txt

.PHONY: run
run-flask: ## Run the app locally
	FLASK_APP=application.py FLASK_ENV=development flask run -p 7000

.PHONY: test
test: ## Run all tests
	py.test tests/
	isort --check-only app tests
	flake8 .

.PHONY: freeze-requirements
freeze-requirements: ## create static requirements.txt
	pip install --upgrade pip-tools
	pip-compile requirements.in

## DEPLOYMENT

.PHONY: preview
preview:
	$(eval export CF_SPACE=preview)
	$(eval export DNS_NAME=documents.notify.works)
	cf target -s ${CF_SPACE}

.PHONY: staging
staging:
	$(eval export CF_SPACE=staging)
	$(eval export DNS_NAME=documents.staging-notify.works)
	cf target -s ${CF_SPACE}

.PHONY: production
production:
	$(eval export CF_SPACE=production)
	$(eval export DNS_NAME=documents.service.gov.uk)
	cf target -s ${CF_SPACE}

.PHONY: generate-manifest
generate-manifest: ## Generate manifest for the app
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))

	$(if $(shell which gpg2), $(eval export GPG=gpg2), $(eval export GPG=gpg))
	$(if ${GPG_PASSPHRASE_TXT}, $(eval export DECRYPT_CMD=echo -n $$$${GPG_PASSPHRASE_TXT} | ${GPG} --quiet --batch --passphrase-fd 0 --pinentry-mode loopback -d), $(eval export DECRYPT_CMD=${GPG} --quiet --batch -d))

	@jinja2 --strict manifest.yml.j2 \
	    -D environment=${CF_SPACE} --format=yaml \
	    <(${DECRYPT_CMD} ${NOTIFY_CREDENTIALS}/credentials/${CF_SPACE}/document-download/paas-environment.gpg) 2>&1

.PHONY: cf-login
cf-login: ## Log in to Cloud Foundry
	$(if ${CF_USERNAME},,$(error Must specify CF_USERNAME))
	$(if ${CF_PASSWORD},,$(error Must specify CF_PASSWORD))
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	@echo "Logging in to Cloud Foundry on ${CF_API}"
	@cf login -a "${CF_API}" -u ${CF_USERNAME} -p "${CF_PASSWORD}" -o "${CF_ORG}" -s "${CF_SPACE}"

.PHONY: cf-deploy
cf-deploy: ## Deploys the app to Cloud Foundry
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	@cf app --guid ${CF_APP} || exit 1

	# cancel any existing deploys to ensure we can apply manifest (if a deploy is in progress you'll see ScaleDisabledDuringDeployment)
	cf cancel-deployment ${CF_APP} || true
	# generate manifest (including secrets) and write it to CF_MANIFEST_PATH (in /tmp/)
	make -s CF_APP=${CF_APP} generate-manifest > ${CF_MANIFEST_PATH}
	# reads manifest from CF_MANIFEST_PATH
	cf push ${CF_APP} --strategy=rolling -f ${CF_MANIFEST_PATH}
	# delete old manifest file
	rm ${CF_MANIFEST_PATH}

.PHONY: cf-rollback
cf-rollback: ## Rollbacks the app to the previous release
	cf cancel-deployment ${CF_APP}
	rm -f ${CF_MANIFEST_PATH}

.PHONY: cf-create-cdn-route
cf-create-cdn-route:
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	$(if ${DNS_NAME},,$(error Must specify DNS_NAME))
	cf create-service cdn-route cdn-route documents-cdn-route -c '{"domain": "${DNS_NAME}"}'
