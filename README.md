# document-download-api
Document Download API


# install steps:

### the docker way
```bash
make build-with-docker
docker run make run
```

### the local way
```bash
mkvirtualenv -p python3 document-download-api
brew install libmagic
pip install -r requirements-dev.txt
make run
```

## Updating application dependencies

`requirements.txt` file is generated from the `requirements-app.txt` in order to pin
versions of all nested dependencies. If `requirements-app.txt` has been changed (or
we want to update the unpinned nested dependencies) `requirements.txt` should be
regenerated with

```
make freeze-requirements
```

`requirements.txt` should be committed alongside `requirements-app.txt` changes.

## antivirus

document download calls the antivirus app on upload. This is enabled by default on
all environments (including unit tests) except for local development. If you wish
to run with antivirus locally set `ANTIVIRUS_ENABLED=1` in your environment.
