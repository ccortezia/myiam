import os


LOGGING = {
    'version': 1,
    'formatters': {
        'simple': {
            'format': '[%(levelname)-7s][%(asctime)s][%(threadName)s][%(name)s] %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
            'level': 'DEBUG'
        },
        'null': {
            'class': 'logging.NullHandler',
            'formatter': 'simple',
            'level': 'DEBUG'
        },
        'file': {
            'class': 'logging.NullHandler',
            'formatter': 'simple',
            'level': 'DEBUG'
        }
    },
    'root': {
        'level': 'DEBUG',
        'handlers': ['console']
    },
    'loggers': {
        'gunicorn.error':     {'propagate': False, 'level': 'DEBUG', 'handlers': ['console']},
        'gunicorn.access':    {'propagate': False, 'level': 'DEBUG', 'handlers': ['null']},
        'werkzeug':           {'propagate': False, 'level': 'DEBUG', 'handlers': ['console']},
        'sqlalchemy':         {'propagate': False, 'level': 'ERROR', 'handlers': ['console']},
        'myiam_api':          {'propagate': False, 'level': 'DEBUG', 'handlers': ['console']},
        'myiam_api.security': {'propagate': False, 'level': 'ERROR', 'handlers': ['console']},
    }
}
