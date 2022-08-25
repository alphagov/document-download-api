# document-download-api

## Setting up

### Python version

Check the version is [runtime.txt](runtime.txt)

### Pre-commit

We use [pre-commit](https://pre-commit.com/) to ensure that committed code meets basic standards for formatting, and will make basic fixes for you to save time and aggravation.

Install pre-commit system-wide with, eg `brew install pre-commit`. Then, install the hooks in this repository with `pre-commit install --install-hooks`.

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

## Further documentation

- [Updating dependencies](https://github.com/alphagov/notifications-manuals/wiki/Dependencies)
