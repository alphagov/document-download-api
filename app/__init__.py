from flask import Flask
from gds_metrics import GDSMetrics
from notifications_utils import logging, request_helper

from app.config import configs
from app.utils.antivirus import AntivirusClient
from app.utils.store import DocumentStore

document_store = DocumentStore() # noqa, has to be imported before views
antivirus_client = AntivirusClient() # noqa
metrics = GDSMetrics() # noqa

from .download.views import download_blueprint  # noqa
from .upload.views import upload_blueprint  # noqa


def create_app():
    application = Flask('app')
    application.config.from_object(configs[application.env])

    request_helper.init_app(application)
    logging.init_app(application)

    document_store.init_app(application)
    antivirus_client.init_app(application)
    metrics.init_app(application)

    application.register_blueprint(download_blueprint)
    application.register_blueprint(upload_blueprint)

    return application
