from flask_env import MetaFlaskEnv


class Config(metaclass=MetaFlaskEnv):
    DEBUG = False

    SECRET_KEY = None
    AUTH_TOKENS = None

    DOCUMENTS_BUCKET = None

    # map of file extension to MIME TYPE.
    ALLOWED_FILE_TYPES = {
        'pdf': 'application/pdf',
        'csv': 'text/csv',
        'txt': 'text/plain',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    }

    MAX_CONTENT_LENGTH = 2 * 1024 * 1024 + 1024

    FRONTEND_HOSTNAME = None

    NOTIFY_APP_NAME = None
    NOTIFY_LOG_PATH = 'application.log'

    ANTIVIRUS_API_HOST = None
    ANTIVIRUS_API_KEY = None

    ANTIVIRUS_ENABLED = True

    HTTP_SCHEME = 'https'
    FRONTEND_HOSTNAME = None


class Test(Config):
    DEBUG = True

    # used during tests as a domain name
    SERVER_NAME = 'document-download.test'

    SECRET_KEY = 'test-secret'
    AUTH_TOKENS = 'test-token:test-token-2'

    DOCUMENTS_BUCKET = 'test-bucket'

    ANTIVIRUS_API_HOST = 'https://test-antivirus'
    ANTIVIRUS_API_KEY = 'test-antivirus-secret'

    FRONTEND_HOSTNAME = 'document-download-frontend-test'


class Development(Config):
    DEBUG = True

    SECRET_KEY = 'secret-key'
    AUTH_TOKENS = 'auth-token'

    DOCUMENTS_BUCKET = 'development-document-download'

    ANTIVIRUS_API_HOST = 'http://localhost:6016'
    ANTIVIRUS_API_KEY = 'test-key'
    ANTIVIRUS_ENABLED = False

    HTTP_SCHEME = 'http'
    FRONTEND_HOSTNAME = 'localhost:7001'


class Preview(Config):
    DOCUMENTS_BUCKET = 'preview-document-download'


class Staging(Config):
    DOCUMENTS_BUCKET = 'staging-document-download'


class Production(Config):
    DOCUMENTS_BUCKET = 'production-document-download'


configs = {
    'test': Test,
    'development': Development,
    'preview': Preview,
    'staging': Staging,
    'production': Production,
}
