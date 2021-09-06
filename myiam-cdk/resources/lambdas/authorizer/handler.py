import re
import json
import boto3
import myiam
import logging
import functools
import jsonpath_ng
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


def sentry_traced(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with sentry_sdk.start_span(op=fn.__name__):
            return fn(*args, **kwargs)
    return wrapper


logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")

ddbt = dynamodb.Table("myiam")


def handle(event, context):

    logger.info(json.dumps(event))

    # Step 1: tries to determine who is the caller.
    principal = resolve_principal(event)

    if not principal:
        logger.info("access denied: unable to determine access principal")
        return make_apig_authorizer_policy(event, "deny")

    # Step 2: tries to determine what role the caller assumed for this access attempt.
    assumed_role = resolve_role(event, principal)

    if not assumed_role:
        logger.info("access denied: unable to determine the assumed role")
        return make_apig_authorizer_policy(event, "deny")

    # Step 3: tries to determine what action the caller wants to perform.
    action_name, resource_uri = resolve_action(event)

    if not action_name:
        logger.info("access denied: unable to resolve action name from request")
        return make_apig_authorizer_policy(event, "deny")

    if not resource_uri:
        logger.info("access denied: unable to resolve resource uri from request")
        return make_apig_authorizer_policy(event, "deny")

    # Step 4: tries to determine what security policies applies to the caller.
    policy_names = find_applicable_policies(event, principal, assumed_role)

    if not policy_names:
        logger.info("access denied: no applicable policies found")
        return make_apig_authorizer_policy(event, "deny")

    # Step 5: fetch indexed evaluation rules out of the applicable policy names.
    evaluation_rules = find_rules(event, action_name, resource_uri, policy_names)

    if not evaluation_rules:
        logger.info("access denied: no evaluation rules found")
        return make_apig_authorizer_policy(event, "deny")

    # Step 6: determines whether the access attempt should be allowed or not.
    evaluation_result = evaluate_access_attempt(event, evaluation_rules)

    logger.info(
        json.dumps(
            {
                "action_name": action_name,
                "resource_uri": resource_uri,
                "assumed_role": assumed_role,
                "applicable_policies": policy_names,
                "evaluation_result": evaluation_result,
            }
        )
    )

    # Step 8: return API Gateway Lambda Authorizer Policy to enforce authorization.
    return make_apig_authorizer_policy(event, evaluation_result)


# ------------------------------------------------------------------------------


@sentry_traced
def resolve_principal(event):
    # TODO: implement once authentication mechanism is in place.
    return "someone"


@sentry_traced
def resolve_role(event, principal):
    # NOTE: real authorization token resolution is not yet performed.
    # Instead, the assumed role is naively resolved out of the header.
    return event["headers"]["authorizer"]


@sentry_traced
def resolve_action(event):
    request_context = event["requestContext"]
    http_method = request_context["httpMethod"]
    http_path = request_context["path"]
    request_key = f"api:{http_method}:{http_path}"

    for item in myiam.describe_resolver(ddbt, request_key):
        if item["sk"] == "resolver#mapping":
            action_name = item["action"]
            # resource = item["resource"]  # TODO: implement dynamic resource resolution
            resource = event["headers"]["resource"]
            break
    else:
        return None, None

    for placeholder_slot_expr in re.findall(r"{([^}]+)}", resource):
        # TODO: handle parsing exception.
        expr = jsonpath_ng.parse(placeholder_slot_expr)
        # TODO: handle void expr resolution.
        # TODO: handle ambiguous expr resolution.
        placeholder_slot = f"{{{placeholder_slot_expr}}}"
        placeholder_value = expr.find(event)[0].value
        resource = resource.replace(placeholder_slot, placeholder_value)

    return action_name, resource


@sentry_traced
def find_applicable_policies(event, principal, assumed_role):
    # TODO: capture applicable policies directly associated to principal
    # TODO: capture applicable policies indirectly associated to principal (groups)
    return myiam.find_policy_names_matching_role(ddbt, assumed_role)


@sentry_traced
def find_rules(event, action_name, resource_name, policy_names):
    return myiam.find_evaluation_rules(
        ddbt,
        action_name=action_name,
        resource_name=resource_name,
        policy_names=policy_names,
        # TODO: implement context extraction to enable Policy conditions.
        context={},
    )


@sentry_traced
def evaluate_access_attempt(event, evaluation_rules):
    # TODO: enrich calculation process and emit debugging information.
    return myiam.calculate_allowance(ddbt, [_["rule_effect"] for _ in evaluation_rules])


def make_apig_authorizer_policy(event, evaluation_result):

    api_id = event["requestContext"]["apiId"]
    api_resource_root = f"arn:aws:execute-api:us-east-1:583723262561:{api_id}"

    return {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow" if evaluation_result == "allow" else "Deny",
                    # NOTE: consider more granular authorization based on request paths.
                    "Resource": f"{api_resource_root}/*",
                }
            ],
        },
    }
