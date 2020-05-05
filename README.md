# document-download-api
Document Download API


# install steps:

### the docker way
```bash
make docker-build
docker run govuk/document-download-api:<GIT_COMMIT> make run
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
