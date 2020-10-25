import json
import boto3
from myiam import list_users


dynamodb = boto3.resource("dynamodb")

ddbt = dynamodb.Table("myiam")


def handle(event, context):

    print(json.dumps(event))
    # print(vars(context))

    # Dummy dynamodb access test to validate stack deployment and permissions.
    # Actual implementation would perform different calls.
    print(json.dumps(list_users(ddbt)))

    api_id = event["requestContext"]["apiId"]

    resource = f"arn:aws:execute-api:us-east-1:583723262561:{api_id}/*"

    # authorization_token = event["headers"]["Authorization"]

    return {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": resource
                }
            ]
        }
    }
