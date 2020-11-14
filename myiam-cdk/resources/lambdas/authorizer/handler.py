import json
import boto3
import myiam
import logging

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
    action_name = resolve_action(event)

    if not action_name:
        logger.info("access denied: unable to resolve action name from request")
        return make_apig_authorizer_policy(event, "deny")

    # Step 4: tries to determine the resource the caller wants to access.
    resource_name = resolve_resource(event)

    if not resource_name:
        logger.info("access denied: unable to resolve resource name from request")
        return make_apig_authorizer_policy(event, "deny")

    # Step 5: tries to determine what security policies applies to the caller.
    policy_names = find_applicable_policies(event, principal, assumed_role)

    if not policy_names:
        logger.info("access denied: no applicable policies found")
        return make_apig_authorizer_policy(event, "deny")

    # Step 6: fetch indexed evaluation rules out of the applicable policy names.
    evaluation_rules = find_rules(event, action_name, resource_name, policy_names)

    if not evaluation_rules:
        logger.info("access denied: no evaluation rules found")
        return make_apig_authorizer_policy(event, "deny")

    # Step 7: determines whether the access attempt should be allowed or not.
    evaluation_result = evaluate_access_attempt(event, evaluation_rules)

    logger.info(
        json.dumps(
            {
                "action_name": action_name,
                "assumed_role": assumed_role,
                "applicable_policies": policy_names,
                "evaluation_result": evaluation_result,
            }
        )
    )

    # Step 8: return API Gateway Lambda Authorizer Policy to enforce authorization.
    return make_apig_authorizer_policy(event, evaluation_result)


# ------------------------------------------------------------------------------


def resolve_principal(event):
    # TODO: implement once authentication mechanism is in place.
    return "someone"


def resolve_role(event, principal):
    # NOTE: real authorization token resolution is not yet performed.
    # Instead, the assumed role is naively resolved out of the header.
    return event["headers"]["authorizer"]


def resolve_action(event):
    request_context = event["requestContext"]
    http_method = request_context["httpMethod"]
    http_path = request_context["path"]

    return myiam.find_action_name_from_access_request(
        datastore=ddbt,
        access_request={"http_method": http_method, "http_path": http_path},
        # TODO: properly infer domain to allow this lambda to protect other APIs
        route_domain_reader=lambda _: "myiam",
    )


def resolve_resource(event):
    # TODO: implement resource resolution routine
    return "unknown"


def find_applicable_policies(event, principal, assumed_role):
    # TODO: capture applicable policies directly associated to principal
    # TODO: capture applicable policies indirectly associated to principal (groups)
    return myiam.find_policy_names_matching_role(ddbt, assumed_role)


def find_rules(event, action_name, resource_name, policy_names):
    return myiam.find_evaluation_rules(
        ddbt,
        action_name=action_name,
        resource_name="unknown",
        policy_names=policy_names,
        # TODO: implement context extraction to enable Policy conditions.
        context={},
    )


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
