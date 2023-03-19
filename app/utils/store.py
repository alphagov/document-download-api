import os
import re
import uuid
from datetime import date, timedelta
from urllib.parse import urlencode

import boto3
from botocore.exceptions import ClientError as BotoClientError
from dateutil import parser
from flask import current_app

from app.utils.hasher import Hasher


class DocumentStoreError(Exception):
    pass


class DocumentBlocked(Exception):
    pass


class DocumentExpired(Exception):
    pass


class DocumentStore:
    _hasher = Hasher()

    def __init__(self, bucket=None):
        self.s3 = boto3.client("s3")
        self.bucket = bucket

    def init_app(self, app):
        self.bucket = app.config["DOCUMENTS_BUCKET"]

    def check_for_blocked_document(self, service_id, document_id):
        """Raises an exception if access to the document has been blocked after creation

        This should be checked before any document access. This might be used to quickly prevent anyone from accessing
        a file that a service has sent out accidentally.

        Note that the `blocked` tag key MUST be in lowercase.
        """
        try:
            tags = {
                item["Key"]: item["Value"]
                for item in self.s3.get_object_tagging(
                    Bucket=self.bucket, Key=self.get_document_key(service_id, document_id)
                )["TagSet"]
            }
        except BotoClientError as e:
            if e.response["Error"].get("ResourceType") == "DeleteMarker":
                # The S3 object has been marked as expired (eg by our retention period lifecycle policy)
                # We should treat is as not existing
                raise DocumentExpired("The document is no longer available") from e

            raise e

        if tags.get("blocked", "false").lower() in {"true", "yes"}:
            raise DocumentBlocked("Access to the document has been blocked")

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
            current_app.logger.info(f"Enabling email confirmation flow for {service_id}/{document_id}")

        tags = {"service-id": service_id}

        if retention_period:
            tags["retention-period"] = retention_period
            current_app.logger.info(
                f"Setting custom retention period for {service_id}/{document_id}: {retention_period}"
            )

        self.s3.put_object(
            Bucket=self.bucket,
            Key=self.get_document_key(service_id, document_id),
            Body=document_stream,
            ContentType=mimetype,
            SSECustomerKey=encryption_key,
            SSECustomerAlgorithm="AES256",
            Tagging=urlencode(tags),
            **extra_kwargs,
        )

        return {"id": document_id, "encryption_key": encryption_key}

    def get(self, service_id, document_id, decryption_key):
        """
        decryption_key should be raw bytes
        """
        try:
            self.check_for_blocked_document(service_id, document_id)
            document = self.s3.get_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )

        except (DocumentBlocked, DocumentExpired) as e:
            raise DocumentStoreError(str(e)) from e
        except BotoClientError as e:
            raise DocumentStoreError(e.response["Error"]) from e

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
            self.check_for_blocked_document(service_id, document_id)
            metadata = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )

            expiry_date = self._convert_expiry_date_to_date_object(metadata["Expiration"])

            return {
                "mimetype": metadata["ContentType"],
                "confirm_email": self.get_email_hash(metadata) is not None,
                "size": metadata["ContentLength"],
                "available_until": str(expiry_date),
            }
        except (DocumentBlocked, DocumentExpired):
            return None
        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                return None
            raise DocumentStoreError(e.response["Error"])

    @staticmethod
    def _convert_expiry_date_to_date_object(raw_expiry_date: str) -> date:
        pattern = re.compile(r'([^=\s]+?)="(.+?)"')
        expiry_date_as_dict = dict(pattern.findall(raw_expiry_date))

        expiry_date_string = expiry_date_as_dict["expiry-date"]

        timezone = expiry_date_string.split()[-1]
        if timezone != "GMT":
            current_app.logger.warning(f"AWS S3 object expiration has unhandled timezone: {timezone}")

        expiry_date = parser.parse(expiry_date_string)
        expiry_date = expiry_date.date() - timedelta(days=1)

        return expiry_date

    def generate_encryption_key(self):
        return os.urandom(32)

    def get_document_key(self, service_id, document_id):
        return "{}/{}".format(service_id, document_id)

    def authenticate(self, service_id: str, document_id: str, decryption_key: bytes, email_address: str) -> bool:
        """
        email_address needs to be in a validated and known-good format before being passed to this method
        """
        try:
            self.check_for_blocked_document(service_id, document_id)
            response = self.s3.head_object(
                Bucket=self.bucket,
                Key=self.get_document_key(service_id, document_id),
                SSECustomerKey=decryption_key,
                SSECustomerAlgorithm="AES256",
            )
        except (DocumentBlocked, DocumentExpired):
            return False
        except BotoClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise DocumentStoreError(e.response["Error"]) from e

        hashed_email = self.get_email_hash(response)

        if not hashed_email:
            return False

        return self._hasher.verify(value=email_address, hash_to_verify=hashed_email)

    @staticmethod
    def get_email_hash(boto_response):
        return boto_response.get("Metadata", {}).get("hashed-recipient-email", None)
