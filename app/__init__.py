from flask import Flask
from notifications_utils import logging, request_helper
from gds_metrics import GDSMetrics

from app.config import configs
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

    request_helper.init_app(application)
    logging.init_app(application)

    document_store.init_app(application)
    antivirus_client.init_app(application)
    metrics.init_app(application)

    application.register_blueprint(download_blueprint)
    application.register_blueprint(upload_blueprint)

    return application
