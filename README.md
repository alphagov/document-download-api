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

## Further documentation

- [Updating dependencies](https://github.com/alphagov/notifications-manuals/wiki/Dependencies)
