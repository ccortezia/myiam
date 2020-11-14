import json
import boto3
import logging
import myiam

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")

ddbt = dynamodb.Table("myiam")


def handle(event, context):

    logger.info(json.dumps(event))

    for record in event["Records"]:

        if _should_derive_policy_statement_rules(record):
            rules = _derive_policy_statement_rules(record)
            logger.info(json.dumps({"event": "RULES_DERIVED", "rules": rules}))

        if _should_cleanup_policy_statement_rules(record):
            rules = _cleanup_policy_statement_rules(record)
            logger.info(json.dumps({"event": "RULES_REMOVED", "rules": rules}))


def _should_derive_policy_statement_rules(record):

    if record["eventName"] != "INSERT":
        return False

    pk, sk = _get_pk_sk(record)
    is_policy_pk = pk.startswith("policy#")
    is_statement_sk = sk.startswith("sid#")
    is_rule_sk = sk.count("#") == 2

    return is_policy_pk and is_statement_sk and (not is_rule_sk)


def _should_cleanup_policy_statement_rules(record):

    if record["eventName"] != "REMOVE":
        return False

    pk, sk = _get_pk_sk(record)
    is_policy_pk = pk.startswith("policy#")
    is_rule_sk = sk.count("#") == 2

    return is_policy_pk and (not is_rule_sk)


def _derive_policy_statement_rules(record):

    # Convert statement into rules
    rules = myiam.convert_policy_statement_into_rules(
        {
            "pk": record["dynamodb"]["NewImage"]["pk"]["S"],
            "sk": record["dynamodb"]["NewImage"]["sk"]["S"],
            "effect": record["dynamodb"]["NewImage"]["effect"]["S"],
            "resources": [record["dynamodb"]["NewImage"]["resources"]["S"]],
            "actions": [record["dynamodb"]["NewImage"]["actions"]["S"]],
        }
    )

    # Insert new rules for statement
    for rule in rules:
        # TODO: handle ddbt.meta.client.exceptions.ConditionalCheckFailedException for
        # uniqueness failures, to avoid crashing the streaming Lambda.
        myiam.create_rule(ddbt, **rule)

    return rules


def _cleanup_policy_statement_rules(record):
    # Remove existing rules for statement.
    pk, sk = _get_pk_sk(record)
    policy_name = pk.split("#")[-1]
    statement_id = sk.split("#")[-1]
    rules = myiam.delete_rules_by_sid(ddbt, policy_name, statement_id)
    return rules


def _get_pk_sk(record):
    pk = record["dynamodb"]["Keys"].get("pk").get("S", "")
    sk = record["dynamodb"]["Keys"].get("sk").get("S", "")
    return pk, sk
