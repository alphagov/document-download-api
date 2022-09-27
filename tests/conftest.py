from contextlib import contextmanager

import pytest
from flask.testing import FlaskClient

from app import create_app


@pytest.fixture(scope="session")
def app():
    app = create_app()

    class TestClient(FlaskClient):
        def open(self, *args, **kwargs):
            kwargs["headers"] = {
                "Authorization": "Bearer {}".format(app.config["AUTH_TOKENS"].split(":")[0]),
                **(kwargs.get("headers", {})),
            }

            return super().open(*args, **kwargs)

    app.test_client_class = TestClient

    ctx = app.app_context()
    ctx.push()

    yield app

    ctx.pop()


@pytest.fixture()
def client(app):

    with app.test_client() as client:
        yield client


@contextmanager
def set_config(app, **kwargs):
    old_values = {}

    for key, value in kwargs.items():
        old_values[key], app.config[key] = app.config.get(key), value

    yield

    for key, value in old_values.items():
        app.config[key] = value


class Matcher:
    def __init__(self, description, key):
        self.key = key
        self.description = description

    def __eq__(self, other):
        return self.key(other)

    def __repr__(self):
        return "<Matcher: {}>".format(self.description)
