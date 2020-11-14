LOGGING = {
    "version": 1,
    "formatters": {
        "concise": {"format": "[%(levelname)-7s] %(message)s"},
        "timestamped": {
            "format": "[%(levelname)-7s][%(asctime)s][%(name)s] %(message)s"
        },
    },
    "handlers": {
        "stream": {
            "class": "logging.StreamHandler",
            "formatter": "timestamped",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "concise",
        },
        "null": {
            "class": "logging.NullHandler",
            "formatter": "timestamped",
        },
    },
    "root": {"level": "DEBUG", "handlers": ["stream"]},
    "loggers": {
        "boto3": {"level": "ERROR"},
        "werkzeug": {"level": "DEBUG"},
        "sqlalchemy": {"level": "ERROR"},
        "myiam_api": {"level": "ERROR"},
        "myiam_api.cli": {"level": "INFO", "handlers": ["console"], "propagate": False},
    },
}
