import os

from flask_env import MetaFlaskEnv

if os.environ.get("VCAP_SERVICES"):
    # on cloudfoundry, config is a json blob in VCAP_SERVICES - unpack it, and populate
    # standard environment variables from it
    from app.cloudfoundry_config import extract_cloudfoundry_config

    extract_cloudfoundry_config()


class Config(metaclass=MetaFlaskEnv):
    SERVER_NAME = os.getenv("SERVER_NAME")
    DEBUG = False

    SECRET_KEY = os.environ.get("SECRET_KEY")
    AUTH_TOKENS = None

    DOCUMENTS_BUCKET = None

    # map of file extension to MIME TYPE.
    ALLOWED_FILE_TYPES = {
        "application/pdf": "pdf",
        "text/csv": "csv",
        "text/plain": "txt",
        "application/json": "json",
        "application/msword": "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.oasis.opendocument.text": "odt",
        "application/rtf": "rtf",
        "text/rtf": "rtf",
    }

    MAX_CONTENT_LENGTH = 2 * 1024 * 1024 + 1024

    NOTIFY_APP_NAME = None
    NOTIFY_LOG_PATH = "application.log"

    ANTIVIRUS_API_HOST = None
    ANTIVIRUS_API_KEY = None

    ANTIVIRUS_ENABLED = True

    HTTP_SCHEME = "https"
    FRONTEND_HOSTNAME = None
    DOCUMENT_DOWNLOAD_API_HOSTNAME = None

    REDIS_URL = os.getenv("REDIS_URL")
    REDIS_ENABLED = False if os.environ.get("REDIS_ENABLED") == "0" else True

    DOCUMENT_AUTHENTICATION_RATE_LIMIT = int(os.getenv("DOCUMENT_AUTHENTICATION_RATE_LIMIT", "50"))
    DOCUMENT_AUTHENTICATE_RATE_INTERVAL_SECONDS = int(os.getenv("DOCUMENT_AUTHENTICATE_RATE_INTERVAL_SECONDS", "300"))


class Test(Config):
    DEBUG = True

    SECRET_KEY = "test-secret"
    AUTH_TOKENS = "test-token:test-token-2"

    DOCUMENTS_BUCKET = "test-bucket"

    ANTIVIRUS_API_HOST = "https://test-antivirus"
    ANTIVIRUS_API_KEY = "test-antivirus-secret"

    HTTP_SCHEME = "http"
    FRONTEND_HOSTNAME = "document-download-frontend-test"
    DOCUMENT_DOWNLOAD_API_HOSTNAME = f"download.{FRONTEND_HOSTNAME}"

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    REDIS_ENABLED = os.environ.get("REDIS_ENABLED") == "1"


class Development(Config):
    DEBUG = True

    SECRET_KEY = "secret-key"
    AUTH_TOKENS = "auth-token"

    DOCUMENTS_BUCKET = "development-document-download"

    ANTIVIRUS_API_HOST = "http://localhost:6016"
    ANTIVIRUS_API_KEY = "test-key"
    ANTIVIRUS_ENABLED = False

    HTTP_SCHEME = "http"
    FRONTEND_HOSTNAME = "localhost:7001"
    DOCUMENT_DOWNLOAD_API_HOSTNAME = "localhost:7000"

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    REDIS_ENABLED = os.environ.get("REDIS_ENABLED") == "1"


class Preview(Config):
    # When running on ECS we set the MULTIREGION_ACCESSPOINT_ARN since we access the bucket
    # through the multiregion accesspoint
    DOCUMENTS_BUCKET = os.getenv("MULTIREGION_ACCESSPOINT_ARN", "preview-document-download")


class Staging(Config):
    DOCUMENTS_BUCKET = "staging-document-download"


class Production(Config):
    DOCUMENTS_BUCKET = "production-document-download"


configs = {
    "test": Test,
    "development": Development,
    "preview": Preview,
    "staging": Staging,
    "production": Production,
}
