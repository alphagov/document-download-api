from uuid import UUID
from base64 import urlsafe_b64decode

from flask import Flask
from werkzeug.routing import BaseConverter, ValidationError
from notifications_utils import logging, request_helper
from gds_metrics import GDSMetrics

from app.config import configs
from app.utils.urls import bytes_to_base64
from app.utils.store import DocumentStore
from app.utils.antivirus import AntivirusClient

document_store = DocumentStore() # noqa, has to be imported before views
antivirus_client = AntivirusClient() # noqa
metrics = GDSMetrics() # noqa

from .download.views import download_blueprint
from .upload.views import upload_blueprint


def create_app(environment):
    application = Flask('app')
    application.config.from_object(configs[environment])

    application.url_map.converters['base64_uuid'] = Base64UUIDConverter

    request_helper.init_app(application)
    logging.init_app(application)

    document_store.init_app(application)
    antivirus_client.init_app(application)
    metrics.init_app(application)

    application.register_blueprint(download_blueprint)
    application.register_blueprint(upload_blueprint)

    return application


class Base64UUIDConverter(BaseConverter):
    def to_python(self, value):
        try:
            # uuids are 16 bytes, and will always have two ==s of padding
            return UUID(bytes=urlsafe_b64decode(value.encode('ascii') + b'=='))
        except ValueError:
            raise ValidationError()

    def to_url(self, value):
        try:
            if not isinstance(value, UUID):
                value = UUID(value)
            return bytes_to_base64(value.bytes)
        except (AttributeError, ValueError):
            raise ValidationError()
