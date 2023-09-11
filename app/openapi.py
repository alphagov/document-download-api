import uuid
from typing import ClassVar, Optional

from flask_openapi3 import Tag
from pydantic import BaseModel, Field, ValidationError

healthcheck_tag = Tag(name="healthcheck")
download_tag = Tag(name="download")
upload_tag = Tag(name="upload")


class NotifyValidationError(Exception):
    def __init__(self, override_message=None, original_error=None, *args, **kwargs):
        self.override_message = override_message
        self.original_error = original_error
        super().__init__(*args, **kwargs)


class CustomErrorBaseModel(BaseModel):
    override_errors: ClassVar = {}

    def __init__(self, **kwargs):
        try:
            super().__init__(**kwargs)
        except ValidationError as e:
            for error in e.errors():
                if override := self.override_errors.get((error["type"], error["loc"])):
                    raise NotifyValidationError(override_message=override) from e
            raise NotifyValidationError(original_error=e) from e


class DownloadPath(CustomErrorBaseModel):
    service_id: uuid.UUID = Field(description="The service UUID")
    document_id: uuid.UUID = Field(description="The document UUID")


class DownloadQuery(CustomErrorBaseModel):
    base64_key: str = Field(alias="key", description="The encryption key protecting the document")

    override_errors = {
        ("value_error.missing", ("key",)): "Missing decryption key",
    }


class DownloadBody(CustomErrorBaseModel):
    base64_key: str = Field(alias="key", description="The encryption key protecting the document")
    email_address: str = Field(description="The email address associated with the document on upload")

    override_errors = {
        ("value_error.missing", ("email_address",)): "No email address",
        ("value_error.missing", ("key",)): "Missing decryption key",
    }


class UploadPath(CustomErrorBaseModel):
    service_id: uuid.UUID = Field(description="The service UUID")


class UploadJson(CustomErrorBaseModel):
    base64_document: str = Field(
        alias="document",
        description="Base64-encoded file to store",
    )
    is_csv: Optional[bool] = Field(description="Is the file a CSV?")
    confirmation_email: Optional[str] = Field(
        default="my@email.com",
        description="If set, the user will need to enter their email address before the file can be downloaded.",
    )
    retention_period: Optional[str] = Field(
        description="How long to retain the file for, in the format '<1-72> weeks'", default="26 weeks"
    )

    override_errors = {
        ("value_error.missing", ("document",)): "No document upload",
        ("type_error.bool", ("is_csv",)): "Value for is_csv must be a boolean",
    }
