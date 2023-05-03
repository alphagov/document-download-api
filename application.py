##!/usr/bin/env python

from app.performance import init_performance_monitoring

init_performance_monitoring()

from app import create_app  # noqa

application = create_app()
