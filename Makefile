SHELL := /bin/bash

GIT_COMMIT ?= $(shell git rev-parse HEAD)

CF_API ?= api.cloud.service.gov.uk
NOTIFY_CREDENTIALS ?= ~/.notify-credentials

CF_APP = document-download-api

.PHONY: run
run:
	FLASK_APP=application.py ENVIRONMENT=development flask run -p 7000

.PHONY: test
test:
	py.test --cov=app --cov-report=term-missing tests/
	if [[ ! -z $$COVERALLS_REPO_TOKEN ]]; then coveralls; fi
	flake8 .

.PHONY: preview
preview:
	$(eval export CF_SPACE=preview)
	$(eval export DNS_NAME=download.notify.works)
	cf target -s ${CF_SPACE}

.PHONY: staging
staging:
	$(eval export CF_SPACE=staging)
	$(eval export DNS_NAME=download.staging-notify.works)
	cf target -s ${CF_SPACE}

.PHONY: production
production:
	$(eval export CF_SPACE=production)
	$(eval export DNS_NAME=download.notifications.service.gov.uk)
	cf target -s ${CF_SPACE}

.PHONY: generate-manifest
generate-manifest:
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))

	$(if $(shell which gpg2), $(eval export GPG=gpg2), $(eval export GPG=gpg))
	$(if ${GPG_PASSPHRASE_TXT}, $(eval export DECRYPT_CMD=echo -n $$$${GPG_PASSPHRASE_TXT} | ${GPG} --quiet --batch --passphrase-fd 0 --pinentry-mode loopback -d), $(eval export DECRYPT_CMD=${GPG} --quiet --batch -d))

	@jinja2 --strict manifest.yml.j2 \
	    -D environment=${CF_SPACE} --format=yaml \
	    <(${DECRYPT_CMD} ${NOTIFY_CREDENTIALS}/credentials/${CF_SPACE}/document-download/paas-environment.gpg) 2>&1

.PHONY: cf-push
cf-push:
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	cf push ${CF_APP}-${CF_SPACE} -f <(make -s generate-manifest)

.PHONY: cf-deploy
cf-deploy: ## Deploys the app to Cloud Foundry
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	@cf app --guid ${CF_APP}-${CF_SPACE} || exit 1
	cf rename ${CF_APP}-${CF_SPACE} ${CF_APP}-${CF_SPACE}-rollback
	cf push ${CF_APP}-${CF_SPACE} -f <(make -s generate-manifest)
	cf scale -i $$(cf curl /v2/apps/$$(cf app --guid ${CF_APP}-${CF_SPACE}-rollback) | jq -r ".entity.instances" 2>/dev/null || echo "1") ${CF_APP}-${CF_SPACE}
	cf stop ${CF_APP}-${CF_SPACE}-rollback
	# sleep for 10 seconds to try and make sure that all worker threads (either web api or celery) have finished before we delete
	sleep 10

	# get the new GUID, and find all crash events for that. If there were any crashes we will abort the deploy.
	[ $$(cf curl "/v2/events?q=type:app.crash&q=actee:$$(cf app --guid ${CF_APP}-${CF_SPACE})" | jq ".total_results") -eq 0 ]
	cf delete -f ${CF_APP}-${CF_SPACE}-rollback

.PHONY: cf-rollback
cf-rollback: ## Rollbacks the app to the previous release
	$(if ${CF_APP},,$(error Must specify CF_APP))
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	@cf app --guid ${CF_APP}-${CF_SPACE}-rollback || exit 1
	@[ $$(cf curl /v2/apps/`cf app --guid ${CF_APP}-${CF_SPACE}-rollback` | jq -r ".entity.state") = "STARTED" ] || (echo "Error: rollback is not possible because ${CF_APP}-${CF_SPACE}-rollback is not in a started state" && exit 1)
	cf delete -f ${CF_APP}-${CF_SPACE} || true
	cf rename ${CF_APP}-${CF_SPACE}-rollback ${CF_APP}-${CF_SPACE}

.PHONY: cf-create-cdn-route
cf-create-cdn-route:
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	$(if ${DNS_NAME},,$(error Must specify DNS_NAME))
	cf create-service cdn-route cdn-route document-download-cdn-route -c '{"domain": "${DNS_NAME}"}'

.PHONY: cf-login
cf-login: ## Log in to Cloud Foundry
	$(if ${CF_USERNAME},,$(error Must specify CF_USERNAME))
	$(if ${CF_PASSWORD},,$(error Must specify CF_PASSWORD))
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	@echo "Logging in to Cloud Foundry on ${CF_API}"
	@cf login -a "${CF_API}" -u ${CF_USERNAME} -p "${CF_PASSWORD}" -o "${CF_ORG}" -s "${CF_SPACE}"

.PHONY: docker-build
docker-build:
	docker build --pull \
		--build-arg HTTP_PROXY="${HTTP_PROXY}" \
		--build-arg HTTPS_PROXY="${HTTP_PROXY}" \
		--build-arg NO_PROXY="${NO_PROXY}" \
		-t govuk/document-download-api:${GIT_COMMIT} \
		.

.PHONY: test-with-docker
test-with-docker: docker-build
	docker run --rm \
		-e COVERALLS_REPO_TOKEN=${COVERALLS_REPO_TOKEN} \
		-e CIRCLECI=1 \
		-e CI_BUILD_NUMBER=${BUILD_NUMBER} \
		-e CI_BUILD_URL=${BUILD_URL} \
		-e CI_NAME=${CI_NAME} \
		-e CI_BRANCH=${GIT_BRANCH} \
		-e CI_PULL_REQUEST=${CI_PULL_REQUEST} \
		-e http_proxy="${http_proxy}" \
		-e https_proxy="${https_proxy}" \
		-e NO_PROXY="${NO_PROXY}" \
		govuk/document-download-api:${GIT_COMMIT} \
		make test

.PHONY: build-paas-artifact
build-paas-artifact:  ## Build the deploy artifact for PaaS
	rm -rf target
	mkdir -p target
	git archive -o target/document-download-api.zip HEAD


.PHONY: upload-paas-artifact ## Upload the deploy artifact for PaaS
upload-paas-artifact:
	$(if ${BUILD_NUMBER},,$(error Must specify BUILD_NUMBER))
	$(if ${JENKINS_S3_BUCKET},,$(error Must specify JENKINS_S3_BUCKET))
	aws s3 cp --region eu-west-1 --sse AES256 target/document-download-api.zip s3://${JENKINS_S3_BUCKET}/build/document-download-api/${BUILD_NUMBER}.zip
