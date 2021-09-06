import logging
from apig_wsgi import make_lambda_handler
from myiam_api import app
import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration


sentry_sdk.init(
    traces_sample_rate=1.0,
    integrations=[
        LoggingIntegration(level=logging.INFO, event_level=logging.WARNING),
        AwsLambdaIntegration(timeout_warning=True),
    ]
)

handle = make_lambda_handler(app)
