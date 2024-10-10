##!/usr/bin/env python

from app.performance import init_performance_monitoring

init_performance_monitoring()

from app import create_app  # noqa

from notifications_utils.eventlet import EventletTimeoutMiddleware, using_eventlet  # noqa

application = create_app()

if using_eventlet:
    application.wsgi_app = EventletTimeoutMiddleware(application.wsgi_app, timeout_seconds=30)
