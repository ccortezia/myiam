from apig_wsgi import make_lambda_handler
from myiam_api import app


HTTP_EVENT = {
    "version": "2.0",
    "routeKey": "$default",
    "rawPath": "/1.0.0/list_users",
    "rawQueryString": "",
    "headers": {
        "accept": "*/*",
        "content-length": "0",
        "host": "vuvj0c9z9i.execute-api.us-east-1.amazonaws.com",
        "user-agent": "insomnia/2020.2.1",
        "x-amzn-trace-id": "Root=1-5f6f3806-c27d7a4e4d55f9667355ff90",
        "x-forwarded-for": "200.160.93.27",
        "x-forwarded-port": "443",
        "x-forwarded-proto": "https"
    },
    "requestContext": {
        "accountId": "583723262561",
        "apiId": "vuvj0c9z9i",
        "domainName": "vuvj0c9z9i.execute-api.us-east-1.amazonaws.com",
        "domainPrefix": "vuvj0c9z9i",
        "http": {
            "method": "GET",
            "path": "/1.0.0/list_users",
            "protocol": "HTTP/1.1",
            "sourceIp": "200.160.93.27",
            "userAgent": "insomnia/2020.2.1"
        },
        "requestId": "TeWxCh5bIAMEMGA=",
        "routeKey": "$default",
        "stage": "$default",
        "time": "26/Sep/2020:12:45:58 +0000",
        "timeEpoch": 1601124358509
    },
    "isBase64Encoded": False
}


REST_EVENT = {
    "resource": "/",
    "path": "/",
    "httpMethod": "GET",
    "headers": {
        "accept": "*/*",
        "Host": "1n5kn8pmq8.execute-api.us-east-1.amazonaws.com",
        "User-Agent": "insomnia/2020.2.1",
        "X-Amzn-Trace-Id": "Root=1-5f6f3fc3-ba95f6a14e47a8c40ee1b0e2",
        "X-Forwarded-For": "200.160.93.27",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https"
    },
    "multiValueHeaders": {
        "accept": [
            "*/*"
        ],
        "Host": [
            "1n5kn8pmq8.execute-api.us-east-1.amazonaws.com"
        ],
        "User-Agent": [
            "insomnia/2020.2.1"
        ],
        "X-Amzn-Trace-Id": [
            "Root=1-5f6f3fc3-ba95f6a14e47a8c40ee1b0e2"
        ],
        "X-Forwarded-For": [
            "200.160.93.27"
        ],
        "X-Forwarded-Port": [
            "443"
        ],
        "X-Forwarded-Proto": [
            "https"
        ]
    },
    "queryStringParameters": None,
    "multiValueQueryStringParameters": None,
    "pathParameters": None,
    "stageVariables": None,
    "requestContext": {
        "resourceId": "0n63e60ll4",
        "resourcePath": "/",
        "httpMethod": "GET",
        "extendedRequestId": "TebmkHJuoAMFwYQ=",
        "requestTime": "26/Sep/2020:13:18:59 +0000",
        "path": "/dev",
        "accountId": "583723262561",
        "protocol": "HTTP/1.1",
        "stage": "dev",
        "domainPrefix": "1n5kn8pmq8",
        "requestTimeEpoch": 1601126339549,
        "requestId": "448fe58c-2692-4595-ad0c-e91f8c1aaa5b",
        "identity": {
            "cognitoIdentityPoolId": None,
            "accountId": None,
            "cognitoIdentityId": None,
            "caller": None,
            "sourceIp": "200.160.93.27",
            "principalOrgId": None,
            "accessKey": None,
            "cognitoAuthenticationType": None,
            "cognitoAuthenticationProvider": None,
            "userArn": None,
            "userAgent": "insomnia/2020.2.1",
            "user": None
        },
        "domainName": "1n5kn8pmq8.execute-api.us-east-1.amazonaws.com",
        "apiId": "1n5kn8pmq8"
    },
    "body": None,
    "isBase64Encoded": False
}


def test_awsgi():
    lambda_handler = make_lambda_handler(app)
    lambda_handler(REST_EVENT, None)
