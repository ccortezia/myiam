import boto3
import logging.config
import connexion


def make_app():

    app = connexion.FlaskApp("myiam_api", specification_dir="openapi/")
    app.add_api("myiam.yaml")

    # Get logging configuration.
    app.app.config.from_object("myiam_api.logconfig.default")
    app.app.config.from_envvar("APP_LOGCONFIG", silent=True)

    # Apply logging configuration.
    logging.config.dictConfig(app.app.config["LOGGING"])

    app.app.table = boto3.resource("dynamodb").Table("myiam")

    return app.app
