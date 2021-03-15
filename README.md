# document-download-api
Document Download API


# install steps:

```bash
brew install libmagic
pip install -r requirements-dev.txt
make run-flask
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
