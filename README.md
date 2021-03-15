# document-download-api

## Setting up

### Python version

Check the version is [runtime.txt](runtime.txt)

### libmagic

This is a library we use to detect file types.

```
brew install libmagic
```

## To run the application

```bash
# install dependencies, etc.
make bootstrap

make run-flask
```

## To test the application

```bash
# install dependencies, etc.
make bootstrap

make test
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
