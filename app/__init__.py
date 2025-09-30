import mimetypes
import os
from collections.abc import Callable
from contextvars import ContextVar

from flask import Flask, current_app, jsonify
from gds_metrics import GDSMetrics
from notifications_utils import request_helper
from notifications_utils.clients.antivirus.antivirus_client import AntivirusClient
from notifications_utils.clients.redis.redis_client import RedisClient
from notifications_utils.eventlet import EventletTimeout
from notifications_utils.local_vars import LazyLocalGetter
from notifications_utils.logging import flask as utils_logging
from werkzeug.local import LocalProxy

from app.config import Config, configs
from app.utils.store import DocumentStore

# must be declared before rest of app is imported to satisfy circular import
# ruff: noqa: E402

metrics = GDSMetrics()
redis_client = RedisClient()

memo_resetters: list[Callable] = []

#
# "clients" that need thread-local copies
#

_document_store_context_var: ContextVar[DocumentStore] = ContextVar("document_store")
get_document_store: LazyLocalGetter[DocumentStore] = LazyLocalGetter(
    _document_store_context_var,
    lambda: DocumentStore(bucket=current_app.config["DOCUMENTS_BUCKET"]),
)
memo_resetters.append(lambda: get_document_store.clear())
document_store = LocalProxy(get_document_store)

_antivirus_client_context_var: ContextVar[AntivirusClient] = ContextVar("antivirus_client")
get_antivirus_client: LazyLocalGetter[AntivirusClient] = LazyLocalGetter(
    _antivirus_client_context_var,
    lambda: AntivirusClient(
        api_host=current_app.config["ANTIVIRUS_API_HOST"],
        auth_token=current_app.config["ANTIVIRUS_API_KEY"],
    ),
)
memo_resetters.append(lambda: get_antivirus_client.clear())
antivirus_client = LocalProxy(get_antivirus_client)


from app.download.views import download_blueprint
from app.file_checks.views import file_checks_blueprint
from app.upload.views import upload_blueprint

mimetypes.init()


def create_app():
    application = Flask("app")

    notify_environment = os.environ["NOTIFY_ENVIRONMENT"]
    if notify_environment in configs:
        application.config.from_object(configs[notify_environment])
    else:
        application.config.from_object(Config)

    request_helper.init_app(application)
    utils_logging.init_app(application)

    metrics.init_app(application)
    redis_client.init_app(application)

    # make sure we handle unicode correctly
    redis_client.redis_store.decode_responses = True

    application.register_blueprint(download_blueprint)
    application.register_blueprint(upload_blueprint)
    application.register_blueprint(file_checks_blueprint)

    @application.errorhandler(EventletTimeout)
    def eventlet_timeout(error):
        application.logger.exception(error)
        return jsonify(result="error", message="Timeout serving request"), 504

    return application


def reset_memos():
    """
    Reset all memos registered in memo_resetters
    """
    for resetter in memo_resetters:
        resetter()
