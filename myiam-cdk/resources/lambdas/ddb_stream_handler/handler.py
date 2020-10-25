import json
import boto3
from myiam import create_rule, delete_rules_by_sid, convert_policy_statement_into_rules


dynamodb = boto3.resource("dynamodb")

ddbt = dynamodb.Table("myiam")


def handle(event, context):

    print(json.dumps(event))

    for record in event["Records"]:

        if _should_derive_policy_statement_rules(record):
            rules = _derive_policy_statement_rules(record)
            print(json.dumps({"event": "RULES_DERIVED", "rules": rules}))

        if _should_cleanup_policy_statement_rules(record):
            rules = _cleanup_policy_statement_rules(record)
            print(json.dumps({"event": "RULES_REMOVED", "rules": rules}))



def _should_derive_policy_statement_rules(record):

    pk, sk = _get_pk_sk(record)

    is_policy_pk = pk.startswith("policy#")
    is_statement_sk = sk.startswith("sid#")
    is_rule_sk = sk.count("#") == 2

    if record["eventName"] != "INSERT":
        False
    if not is_policy_pk:
        False
    if not is_statement_sk:
        False
    if is_rule_sk:
        False
    return True


def _derive_policy_statement_rules(record):

    # Convert statement into rules
    rules = convert_policy_statement_into_rules({
        'pk': record["dynamodb"]["NewImage"]["pk"]["S"],
        'sk': record["dynamodb"]["NewImage"]["sk"]["S"],
        'effect': record["dynamodb"]["NewImage"]["effect"]["S"],
        'resources': [record["dynamodb"]["NewImage"]["resources"]["S"]],
        'actions': [record["dynamodb"]["NewImage"]["actions"]["S"]],
    })

    # Insert new rules for statement
    for rule in rules:
        create_rule(ddbt, **rule)

    return rules


def _cleanup_policy_statement_rules(record):
    # Remove existing rules for statement.
    pk, sk = _get_pk_sk(record)
    policy_name = pk.split("#")[-1]
    statement_id = sk.split("#")[-1]
    rules = delete_rules_by_sid(ddbt, policy_name, statement_id)
    return rules


def _get_pk_sk(record):
    pk = record["dynamodb"]['Keys'].get("pk").get("S", "")
    sk = record["dynamodb"]['Keys'].get("sk").get("S", "")
    return pk, sk
