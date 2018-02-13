##!/usr/bin/env python

import os

from app import create_app


application = create_app(os.environ['ENVIRONMENT'])
