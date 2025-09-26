from flask import jsonify

from .views import file_checks_blueprint


@file_checks_blueprint.errorhandler(413)
def request_entity_too_large(error):
    return jsonify(error="Uploaded file exceeds file size limit"), 413
