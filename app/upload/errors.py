from flask import jsonify

from .views import upload_blueprint


@upload_blueprint.errorhandler(413)
def request_entity_too_large(error):
    return jsonify(error="Uploaded document exceeds file size limit"), 413
