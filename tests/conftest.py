import pytest

from contextlib import contextmanager

from app import create_app


@pytest.fixture(scope='session')
def app():
    app = create_app('test')

    ctx = app.app_context()
    ctx.push()

    yield app

    ctx.pop()


@contextmanager
def set_config(app, **kwargs):
    old_values = {}

    for key, value in kwargs.items():
        old_values[key], app.config[key] = app.config.get(key), value

    yield

    for key, value in old_values.items():
        app.config[key] = value
