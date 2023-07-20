import uuid
from typing import Optional

from flask_openapi3 import Tag
from pydantic import BaseModel, Field

healthcheck_tag = Tag(name="healthcheck")
download_tag = Tag(name="download")
upload_tag = Tag(name="upload")


class DownloadPath(BaseModel):
    service_id: uuid.UUID = Field(description="The service UUID")
    document_id: uuid.UUID = Field(description="The document UUID")


class DownloadQuery(BaseModel):
    base64_key: Optional[str] = Field(alias="key", description="The encryption key protecting the document")


class DownloadBody(BaseModel):
    base64_key: Optional[str] = Field(alias="key", description="The encryption key protecting the document")
    email_address: Optional[str] = Field(description="The email address associated with the document on upload")


class UploadPath(BaseModel):
    service_id: uuid.UUID = Field(description="The service UUID")


class UploadJson(BaseModel):
    base64_document: str = Field(alias="document", description="Base64-encoded file to store")
    is_csv: Optional[bool] = Field(description="Is the file a CSV?")
    confirmation_email: Optional[str] = Field(
        default="my@email.com",
        description="If set, the user will need to enter their email address before the file can be downloaded.",
    )
    retention_period: Optional[str] = Field(
        description="How long to retain the file for, in the format '<1-72> weeks'", default="26 weeks"
    )
