import os
import uuid
from urllib.parse import urlencode

import boto3
from botocore.exceptions import ClientError as BotoClientError

from app.utils.hasher import Hasher


class DocumentStoreError(Exception):
    pass


class DocumentStore:
    _hasher = Hasher()

    def __init__(self, bucket=None):
        self.s3 = boto3.client("s3")
        self.bucket = bucket

    def init_app(self, app):
        self.bucket = app.config["DOCUMENTS_BUCKET"]

    def put(self, service_id, document_stream, *, mimetype, confirmation_email=None, retention_period=None):
        """
        confirmation_email and retention_period need to already be in a validated and known-good format
        by the time they come into this method.

        returns dict {'id': 'some-uuid', 'encryption_key': b'32 byte encryption key'}
        """

        encryption_key = self.generate_encryption_key()
        document_id = str(uuid.uuid4())

        extra_kwargs = {}
        if confirmation_email:
            hashed_recipient_email = self._hasher.hash(confirmation_email)
            extra_kwargs["Metadata"] = {"hashed-recipient-email": hashed_recipient_email}

        if retention_period:
            tags = {"retention-period": retention_period}
            extra_kwargs["Tagging"] = urlencode(tags)

        self.s3.put_object(
            Bucket=self.bucket,
            Key=self.get_document_key(service_id, document_id),
            Body=document_stream,
            ContentType=mimetype,
            SSECustomerKey=encryption_key,
            SSECustomerAlgorithm="AES256",
            **extra_kwargs,
        )

        return {"id": document_id, "encryption_key": encryption_key}

    def get(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """
        try:
            document = self.s3.get_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )

        except BotoClientError as e:
            raise DocumentStoreError(e.response["Error"])

        return {
            "body": document["Body"],
            "mimetype": document["ContentType"],
            "size": document["ContentLength"],
            "metadata": document["Metadata"],
        }

    def get_document_metadata(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """

        try:
            metadata = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )

            return {
                "mimetype": metadata["ContentType"],
                "confirm_email": self.get_email_hash(metadata) is not None,
                "size": metadata["ContentLength"],
            }
        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                return None
            raise DocumentStoreError(e.response["Error"])

    def generate_encryption_key(self):
        return os.urandom(32)

    def get_document_key(self, service_id, document_id):
        return "{}/{}".format(service_id, document_id)

    def authenticate(self, service_id: str, document_id: str, decryption_key: bytes, email_address: str) -> bool:
        """
        email_address needs to be in a validated and known-good format before being passed to this method
        """
        try:
            response = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )

        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False

            return False

        hashed_email = self.get_email_hash(response)

        if not hashed_email:
            return False

        return self._hasher.verify(value=email_address, hash_to_verify=hashed_email)

    @staticmethod
    def get_email_hash(boto_response):
        return boto_response.get("Metadata", {}).get("hashed-recipient-email", None)
