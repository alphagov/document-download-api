# document-download-api

## Setting up

### Python version

Check the version is the same as at the top of [Dockerfile](docker/Dockerfile)


### uv

We use [uv](https://github.com/astral-sh/uv) for Python dependency management. Follow the [install instructions](https://github.com/astral-sh/uv?tab=readme-ov-file#installation) or run:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

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

### Black mid-project reformat

We added the Python auto-formatter `black` to this project after its inception. This required a bulk re-format of existing files, which generated a large and noisy commit. Git blame can be configured to ignore this commit with the following command:

`git config --local blame.ignoreRevsFile .git-blame-ignore-revs`
