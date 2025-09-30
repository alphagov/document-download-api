import mimetypes
from base64 import b64decode, binascii
from hashlib import sha1
from io import BytesIO

from flask import abort, current_app
from notifications_utils.clients.antivirus.antivirus_client import AntivirusError
from notifications_utils.clients.redis import RequestCache
from notifications_utils.recipient_validation.errors import InvalidEmailError

from app import antivirus_client, redis_client
from app.utils import get_mime_type
from app.utils.files import split_filename
from app.utils.validation import (
    clean_and_validate_email_address,
    clean_and_validate_retention_period,
    validate_filename,
)

cache = RequestCache(redis_client)


class FiletypeError(Exception):
    def __init__(self, message=None, status_code=400):
        self.message = message
        self.status_code = status_code


class AntivirusAndMimeTypeCheckError(Exception):
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code


class UploadedFile:
    def __init__(self, *, file_data, is_csv, confirmation_email, retention_period, filename, service_id):
        self.is_csv = is_csv
        self.filename = filename
        self.confirmation_email = confirmation_email
        self.retention_period = retention_period
        self.service_id = service_id
        self.file_data = file_data

    @classmethod
    def from_request_json(cls, data, *, service_id):
        if "document" not in data:
            raise AntivirusAndMimeTypeCheckError("No document upload")

        try:
            raw_content = b64decode(data["document"])
        except (binascii.Error, ValueError) as e:
            raise AntivirusAndMimeTypeCheckError("Document is not base64 encoded") from e

        if len(raw_content) > current_app.config["MAX_DECODED_FILE_SIZE"]:
            abort(413)

        return cls(
            file_data=BytesIO(raw_content),
            is_csv=data.get("is_csv"),
            confirmation_email=data.get("confirmation_email"),
            retention_period=data.get("retention_period"),
            filename=data.get("filename", None),
            service_id=service_id,
        )

    @property
    def is_csv(self):
        return self._is_csv

    @is_csv.setter
    def is_csv(self, value):
        if value is None:
            value = False
        if not isinstance(value, bool):
            raise AntivirusAndMimeTypeCheckError("Value for is_csv must be a boolean")
        self._is_csv = value

    @property
    def confirmation_email(self):
        return getattr(self, "_confirmation_email", None)

    @confirmation_email.setter
    def confirmation_email(self, value):
        if value is None:
            return
        try:
            self._confirmation_email = clean_and_validate_email_address(value)
        except InvalidEmailError as e:
            raise AntivirusAndMimeTypeCheckError(str(e)) from e

    @property
    def retention_period(self):
        return getattr(self, "_retention_period", None)

    @retention_period.setter
    def retention_period(self, value):
        if value is None:
            return
        try:
            self._retention_period = clean_and_validate_retention_period(value)
        except ValueError as e:
            raise AntivirusAndMimeTypeCheckError(str(e)) from e

    @property
    def filename(self):
        return getattr(self, "_filename", None)

    @filename.setter
    def filename(self, value):
        if value is None:
            return
        try:
            self._filename = validate_filename(value)
        except ValueError as e:
            raise AntivirusAndMimeTypeCheckError(str(e)) from e

    @property
    def file_data(self):
        return self._file_data

    @file_data.setter
    def file_data(self, value):
        self._file_data = value
        self.mimetype = self.mimetype_deserialised()

    @property
    def file_data_hash(self):
        contents = bytearray(self.file_data.read())
        self.file_data.seek(0)

        if self.file_extension:
            contents += str(self.file_extension).encode()
        else:
            contents += bytes(self.is_csv)

        contents += str(self.service_id).encode()

        return sha1(contents).hexdigest()

    @property
    def file_extension(self):
        if not self.filename:
            return
        return split_filename(self.filename, dotted=True)[1]

    def mimetype_deserialised(self):
        result = self.mimetype_serialised(self.file_data_hash)
        if "failure" in result:
            raise AntivirusAndMimeTypeCheckError(
                message=result["failure"]["error"],
                status_code=result["failure"]["status_code"],
            )
        return result["success"]["mimetype"]

    @cache.set("file-checks-{file_data_hash}", ttl_in_seconds=86_400)
    def mimetype_serialised(self, file_data_hash):
        if file_data_hash != self.file_data_hash:
            raise RuntimeError("Wrong hash value passed to cache")
        try:
            self.do_virus_scan()
            return {"success": {"mimetype": self._mimetype}}
        except (AntivirusError, FiletypeError) as e:
            return {"failure": {"error": e.message, "status_code": e.status_code}}

    @property
    def _mimetype(self):
        if self.filename:
            mimetype = mimetypes.types_map[self.file_extension]
        else:
            mimetype = get_mime_type(self.file_data)
            # Our mimetype auto-detection sometimes resolves CSV content as text/plain, so we use
            # an explicit POST body parameter `is_csv` from the caller to resolve it as text/csv
            if self.is_csv and mimetype == "text/plain":
                mimetype = "text/csv"
        if mimetype not in current_app.config["MIME_TYPES_TO_FILE_EXTENSIONS"]:
            allowed_file_types = ", ".join(
                sorted({f"'.{x}'" for x in current_app.config["FILE_EXTENSIONS_TO_MIMETYPES"].keys()})
            )
            raise FiletypeError(
                message=f"Unsupported file type '{mimetype}'. Supported types are: {allowed_file_types}"
            )
        return mimetype

    def do_virus_scan(self):
        if not current_app.config["ANTIVIRUS_ENABLED"]:
            return
        try:
            virus_free = antivirus_client.scan(self.file_data)
        except AntivirusError as e:
            raise AntivirusError(message="Antivirus API error", status_code=503) from e
        if not virus_free:
            raise AntivirusError(message="File did not pass the virus scan", status_code=400)
