from flask import current_app
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import BadSignature, SignatureExpired

# can access for 30 days
MAX_AGE_SECONDS = 60 * 60 * 24 * 30


def sign_service_and_document_id(service_id, document_id):
    signer = SecureCookieSessionInterface().get_signing_serializer(current_app)
    return signer.dumps(
        {
            "service_id": service_id,
            "document_id": document_id,
        }
    )


def verify_signed_service_and_document_id(signed_data, expected_service_id, expected_document_id):
    signer = SecureCookieSessionInterface().get_signing_serializer(current_app)
    try:
        data = signer.loads(signed_data, max_age=MAX_AGE_SECONDS)
        return data == {
            "service_id": expected_service_id,
            "document_id": expected_document_id,
        }
    except (BadSignature, SignatureExpired):
        return False
