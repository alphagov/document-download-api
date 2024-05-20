import os


class Config:
    SERVER_NAME = os.getenv("SERVER_NAME")
    DEBUG = False

    SECRET_KEY = os.environ.get("SECRET_KEY")
    AUTH_TOKENS = os.environ.get("AUTH_TOKENS")

    DOCUMENTS_BUCKET = os.getenv("MULTIREGION_ACCESSPOINT_ARN", os.environ.get("DOCUMENTS_BUCKET"))

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
        "text/rtf": "rtf",
        "application/rtf": "rtf",
    }
    FILE_EXTENSIONS_TO_MIMETYPES = {value: key for key, value in ALLOWED_FILE_TYPES.items()}

    MAX_CONTENT_LENGTH = 3 * 1024 * 1024  # 3MiB: Enforced by Flask/Werkzeug to generously allow for b64 size inflation
    MAX_DECODED_FILE_SIZE = (2 * 1024 * 1024) + 1024  # ~2MiB: Enforced by us - max file size after b64decode
    MAX_CUSTOM_FILENAME_LENGTH = 100

    NOTIFY_APP_NAME = os.environ.get("NOTIFY_APP_NAME")

    ANTIVIRUS_API_HOST = os.environ.get("ANTIVIRUS_API_HOST")
    ANTIVIRUS_API_KEY = os.environ.get("ANTIVIRUS_API_KEY")

    ANTIVIRUS_ENABLED = True

    HTTP_SCHEME = "https"
    FRONTEND_HOSTNAME = os.environ.get("FRONTEND_HOSTNAME")
    DOCUMENT_DOWNLOAD_API_HOSTNAME = os.environ.get("DOCUMENT_DOWNLOAD_API_HOSTNAME")

    REDIS_URL = os.getenv("REDIS_URL")

    REDIS_ENABLED = os.environ.get("REDIS_ENABLED") == "1"

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

    REDIS_URL = "redis://localhost:6379/1"


class Development(Config):
    DEBUG = True

    SECRET_KEY = "secret-key"
    AUTH_TOKENS = "auth-token"

    DOCUMENTS_BUCKET = "development-document-download"

    ANTIVIRUS_API_HOST = "http://localhost:6016"
    ANTIVIRUS_API_KEY = "test-key"
    ANTIVIRUS_ENABLED = False

    HTTP_SCHEME = "http"
    FRONTEND_HOSTNAME = os.environ.get("FRONTEND_HOSTNAME", "localhost:7001")
    DOCUMENT_DOWNLOAD_API_HOSTNAME = os.environ.get("DOCUMENT_DOWNLOAD_API_HOSTNAME", "localhost:7000")

    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")


configs = {
    "test": Test,
    "development": Development,
}
