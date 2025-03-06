from gunicorn_config import keepalive, timeout, worker_class, worker_connections, workers


def test_gunicorn_config():
    assert workers == 4
    assert worker_class == "eventlet"
    assert worker_connections == 1_000
    assert keepalive == 90
    assert timeout == 30
