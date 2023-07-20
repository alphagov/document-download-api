import os

from flask import jsonify
from flask_openapi3 import Info, OpenAPI
from gds_metrics import GDSMetrics
from notifications_utils import logging, request_helper
from notifications_utils.clients.redis.redis_client import RedisClient

from app.config import configs
from app.utils.antivirus import AntivirusClient
from app.utils.store import DocumentStore

from .openapi import NotifyValidationError

document_store = DocumentStore()  # noqa, has to be imported before views
antivirus_client = AntivirusClient()  # noqa
metrics = GDSMetrics()  # noqa
redis_client = RedisClient()

from .download.views import download_blueprint  # noqa
from .upload.views import upload_blueprint  # noqa


def create_app():
    application = OpenAPI(
        "app",
        info=Info(title="document-download-api", version="1"),
        doc_prefix="/services/openapi",
        security_schemes={
            "bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "API Key"},
            "cookie": {
                "type": "cookie",
                "in": "cookie",
                "name": "document_access_signed_data",
                "description": (
                    "This cookie is set by document-download-frontend via a valid request to "
                    "the `authenticate_access_to_document` endpoint."
                ),
            },
        },
    )
    application.config.from_object(configs[os.environ["NOTIFY_ENVIRONMENT"]])

    request_helper.init_app(application)
    logging.init_app(application)

    document_store.init_app(application)
    antivirus_client.init_app(application)
    metrics.init_app(application)
    redis_client.init_app(application)

    # make sure we handle unicode correctly
    redis_client.redis_store.decode_responses = True

    application.register_api(download_blueprint)
    application.register_api(upload_blueprint)

    @application.errorhandler(NotifyValidationError)
    def notify_error_handler(error: NotifyValidationError):
        # We override pydantic's native validation errors with our custom one so that we can return a 400 instead of
        # a 422, which is what flask-openapi3 returns. We don't have this behaviour on Notify and so 400 is more
        # consistent with what we would expect.
        if error.override_message:
            return jsonify(error=error.override_message), 400

        return error.original_error.json(), 400

    return application
