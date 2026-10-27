##!/usr/bin/env python
import os

from notifications_utils import greenlet as utils_greenlet

from app.performance import init_performance_monitoring

init_performance_monitoring()

from app import create_app  # noqa

application = create_app()

if utils_greenlet.using_eventlet or utils_greenlet.using_gevent:
    application.wsgi_app = utils_greenlet.RequestHandlingTimeoutMiddleware(
        application.wsgi_app,
        timeout_seconds=int(os.getenv("HTTP_SERVE_TIMEOUT_SECONDS", 30)),
    )
