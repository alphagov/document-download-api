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
