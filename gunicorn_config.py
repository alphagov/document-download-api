import os

from gds_metrics.gunicorn import child_exit  # noqa

bind = "0.0.0.0:{}".format(os.getenv("PORT"))

workers = 4

worker_class = "eventlet"
worker_connections = 1000

errorlog = "/home/vcap/logs/gunicorn_error.log"
