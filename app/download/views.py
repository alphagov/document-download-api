from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    request,
    send_file,
)
from notifications_utils.base64_uuid import base64_to_bytes

from app import document_store
from app.utils.store import DocumentStoreError

download_blueprint = Blueprint('download', __name__, url_prefix='')


@download_blueprint.route('/services/<uuid:service_id>/documents/<uuid:document_id>', methods=['GET'])
def download_document(service_id, document_id):
    if 'key' not in request.args:
        return jsonify(error='Missing decryption key'), 400

    try:
        key = base64_to_bytes(request.args['key'])
    except ValueError:
        return jsonify(error='Invalid decryption key'), 400

    try:
        document = document_store.get(service_id, document_id, key)
    except DocumentStoreError as e:
        current_app.logger.info(
            'Failed to download document: {}'.format(e),
            extra={
                'service_id': service_id,
                'document_id': document_id,
            }
        )
        return jsonify(error=str(e)), 400

    extension = None
    for ext, mimetypes in current_app.config['ALLOWED_FILE_TYPES'].items():
        if document['mimetype'] in mimetypes:
            extension = ext
            break

    send_file_kwargs = {
        'mimetype': document['mimetype'],
        'attachment_filename': f'{document_id}.{extension}',
        'as_attachment': True,
    }
    if document['mimetype'] == 'application/pdf':
        # Open PDFs in the browser
        send_file_kwargs.update({'as_attachment': False})
    elif document['mimetype'] == 'text/plain':
        # Open raw text files in the browser
        send_file_kwargs.update({'as_attachment': False})

    response = make_response(
        send_file(
            document['body'],
            **send_file_kwargs,
        )
    )
    response.headers['Content-Length'] = document['size']
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'

    return response


@download_blueprint.route('/services/<uuid:service_id>/documents/<uuid:document_id>/check', methods=['GET'])
def check_document_exists(service_id, document_id):
    if 'key' not in request.args:
        return jsonify(error='Missing decryption key'), 400

    try:
        key = base64_to_bytes(request.args['key'])
    except ValueError:
        return jsonify(error='Invalid decryption key'), 400

    try:
        document_exists = document_store.check_document_exists(service_id, document_id, key)
    except DocumentStoreError as e:
        current_app.logger.warning(
            'Failed to check if document exists: {}'.format(e),
            extra={
                'service_id': service_id,
                'document_id': document_id,
            }
        )
        return jsonify(error=str(e)), 400

    response = make_response({'file_exists': str(document_exists)})
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'

    return response
