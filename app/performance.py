import os
from functools import partial


def sentry_sampler(sampling_context, sample_rate: float = 0.0):
    if sampling_context["parent_sampled"]:
        return 1

    return sample_rate


def init_performance_monitoring():
    environment = os.getenv("NOTIFY_ENVIRONMENT").lower()
    allow_pii = os.getenv("SENTRY_ALLOW_PII", "0") == "1"
    sentry_enabled = bool(int(os.getenv("SENTRY_ENABLED", "0")))
    sentry_dsn = os.getenv("SENTRY_DSN")

    if environment and sentry_enabled and sentry_dsn:
        import sentry_sdk

        error_sample_rate = float(os.getenv("SENTRY_ERRORS_SAMPLE_RATE", 0.0))
        trace_sample_rate = float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", 0.0))

        send_pii = True if allow_pii else False
        send_request_bodies = "medium" if allow_pii else "never"

        traces_sampler = partial(sentry_sampler, sample_rate=trace_sample_rate)

        try:
            from app.version import __git_commit__

            release = __git_commit__
        except ImportError:
            release = None

        sentry_sdk.init(
            dsn=sentry_dsn,
            environment=environment,
            sample_rate=error_sample_rate,
            send_default_pii=send_pii,
            request_bodies=send_request_bodies,
            traces_sampler=traces_sampler,
            release=release,
        )
