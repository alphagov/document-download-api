from flask_env import MetaFlaskEnv


class Config(metaclass=MetaFlaskEnv):
    DEBUG = False

    SECRET_KEY = None
    AUTH_TOKENS = None

    DOCUMENTS_BUCKET = None

    PUBLIC_HOSTNAME = None

    NOTIFY_APP_NAME = None
    NOTIFY_LOG_PATH = 'application.log'


class Test(Config):
    DEBUG = True

    SECRET_KEY = 'test-secret'
    AUTH_TOKENS = 'test-token:test-token-2'

    DOCUMENTS_BUCKET = 'test-bucket'


class Development(Config):
    DEBUG = True

    SECRET_KEY = 'secret-key'
    AUTH_TOKENS = 'auth-token'

    DOCUMENTS_BUCKET = 'development-document-download'


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
