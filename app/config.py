import os

from flask_env import MetaFlaskEnv

if os.environ.get("VCAP_SERVICES"):
    # on cloudfoundry, config is a json blob in VCAP_SERVICES - unpack it, and populate
    # standard environment variables from it
    from app.cloudfoundry_config import extract_cloudfoundry_config

    extract_cloudfoundry_config()


class Config(metaclass=MetaFlaskEnv):
    DEBUG = False

    SECRET_KEY = os.environ.get("SECRET_KEY")
    AUTH_TOKENS = None

    DOCUMENTS_BUCKET = None

    # map of file extension to MIME TYPE.
    ALLOWED_FILE_TYPES = {
        "application/pdf": "pdf",
        "text/csv": "csv",
        "text/plain": "txt",
        "application/msword": "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.oasis.opendocument.text": "odt",
        "application/rtf": "rtf",
        "text/rtf": "rtf",
    }

    MAX_CONTENT_LENGTH = 2 * 1024 * 1024 + 1024

    FRONTEND_HOSTNAME = None
    FRONTEND_HOSTNAME_INTERNAL = None

    NOTIFY_APP_NAME = None
    NOTIFY_LOG_PATH = "application.log"

    ANTIVIRUS_API_HOST = None
    ANTIVIRUS_API_KEY = None

    ANTIVIRUS_ENABLED = True

    HTTP_SCHEME = "https"

    REDIS_URL = os.getenv("REDIS_URL")
    REDIS_ENABLED = True

    DOCUMENT_AUTHENTICATION_RATE_LIMIT = int(os.getenv("DOCUMENT_AUTHENTICATION_RATE_LIMIT", "50"))
    DOCUMENT_AUTHENTICATE_RATE_INTERVAL_SECONDS = int(os.getenv("DOCUMENT_AUTHENTICATE_RATE_INTERVAL_SECONDS", "300"))


class Test(Config):
    DEBUG = True

    # used during tests as a domain name
    SERVER_NAME = "document-download.test"

    SECRET_KEY = "test-secret"
    AUTH_TOKENS = "test-token:test-token-2"

    DOCUMENTS_BUCKET = "test-bucket"

    ANTIVIRUS_API_HOST = "https://test-antivirus"
    ANTIVIRUS_API_KEY = "test-antivirus-secret"

    FRONTEND_HOSTNAME = "document-download-frontend-test"
    FRONTEND_HOSTNAME_INTERNAL = "document-download-frontend-internal-test"

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
    FRONTEND_HOSTNAME_INTERNAL = "localhost:7001"

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    REDIS_ENABLED = os.environ.get("REDIS_ENABLED") == "1"


class Preview(Config):
    DOCUMENTS_BUCKET = "preview-document-download"


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
