SHELL := /bin/bash

NOTIFY_CREDENTIALS ?= ~/.notify-credentials

CF_APP = document-download-api


.PHONY: run
run:
	FLASK_APP=application.py FLASK_DEBUG=1 ENVIRONMENT=development flask run -p 7000

.PHONY: preview
preview:
	$(eval export CF_SPACE=preview)
	cf target -s ${CF_SPACE}

.PHONY: generate-manifest
generate-manifest:
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))

	$(if $(shell which gpg2), $(eval export GPG=gpg2), $(eval export GPG=gpg))
	$(if ${GPG_PASSPHRASE_TXT}, $(eval export DECRYPT_CMD=echo -n $$$${GPG_PASSPHRASE_TXT} | ${GPG} --quiet --batch --passphrase-fd 0 --pinentry-mode loopback -d), $(eval export DECRYPT_CMD=${GPG} --quiet --batch -d))

	@./scripts/generate_manifest.py manifest.yml.j2 \
	    <(${DECRYPT_CMD} ${NOTIFY_CREDENTIALS}/credentials/${CF_SPACE}/document-download/paas-environment.gpg) \
	    <(echo environment: ${CF_SPACE})

.PHONY: cf-push
cf-push:
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	cf push ${CF_APP} -f <(make -s generate-manifest)

.PHONY: cf-deploy
cf-deploy: ## Deploys the app to Cloud Foundry
	$(if ${CF_SPACE},,$(error Must specify CF_SPACE))
	@cf app --guid ${CF_APP} || exit 1
	cf rename ${CF_APP} ${CF_APP}-rollback
	cf push ${CF_APP} -f <(make -s generate-manifest)
	cf scale -i $$(cf curl /v2/apps/$$(cf app --guid ${CF_APP}-rollback) | jq -r ".entity.instances" 2>/dev/null || echo "1") ${CF_APP}
	cf stop ${CF_APP}-rollback
	# sleep for 10 seconds to try and make sure that all worker threads (either web api or celery) have finished before we delete
	sleep 10

	# get the new GUID, and find all crash events for that. If there were any crashes we will abort the deploy.
	[ $$(cf curl "/v2/events?q=type:app.crash&q=actee:$$(cf app --guid ${CF_APP})" | jq ".total_results") -eq 0 ]
	cf delete -f ${CF_APP}-rollback
