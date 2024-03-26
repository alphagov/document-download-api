from gds_metrics.gunicorn import child_exit  # noqa
from notifications_utils.gunicorn_defaults import set_gunicorn_defaults


set_gunicorn_defaults(globals())


workers = 4
worker_class = "eventlet"
worker_connections = 1000
keepalive = 90
