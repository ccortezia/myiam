from apig_wsgi import make_lambda_handler
from myiam_api import app


handle = make_lambda_handler(app)
