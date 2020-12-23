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
        if _should_derive_user_group_policy_inheritance(record):
            derived = _derive_user_group_policy_inheritance(record)
            message = json.dumps({"event": "USER_GROUP_POLICIES_INHERITED", "derived": derived})
            logger.info(message)

        if _should_cleanup_user_group_policy_inheritance(record):
            cleaned = _cleanup_user_group_policy_inheritance(record)
            message = json.dumps({"event": "USER_GROUP_POLICIES_DISINHERITED", "cleaned": cleaned})
            logger.info(message)

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


def _should_derive_user_group_policy_inheritance(record):

    if record["eventName"] != "INSERT":
        return False

    pk, sk = _get_pk_sk(record)
    is_group_pk = pk.startswith("group#")
    is_user_sk = sk.startswith("user#")
    is_policy_sk = sk.startswith("policy#")

    return is_group_pk and (is_user_sk or is_policy_sk)


def _should_cleanup_user_group_policy_inheritance(record):

    if record["eventName"] != "REMOVE":
        return False

    pk, sk = _get_pk_sk(record)
    is_group_pk = pk.startswith("group#")
    is_user_sk = sk.startswith("user#")
    is_policy_sk = sk.startswith("policy#")

    return is_group_pk and (is_user_sk or is_policy_sk)


def _derive_user_group_policy_inheritance(record):
    pk, sk = _get_pk_sk(record)
    group_name = pk.split("#")[-1]
    is_user_sk = sk.startswith("user#")
    is_policy_sk = sk.startswith("policy#")
    derived = []

    # NOTE: this query+update sequence creates a race condition with other processes
    # adding or removing policies to the group at this time, and may result in users
    # with missing policies or unexpected policies.

    if is_user_sk:
        # When a group member is added, attach inherited policies to it
        user_name = sk.split("#")[-1]
        items = myiam.describe_group(ddbt, group_name)
        policy_items = [item for item in items if item["sk"].startswith("policy#")]
        policy_names = [item["sk"].split("#")[-1] for item in policy_items]
        for policy_name in policy_names:
            myiam.update_user_inherit_group_policies(ddbt, user_name, group_name, [policy_name])
            derived.append((group_name, user_name, policy_name))

    if is_policy_sk:
        # When a policy is added to a group, attach it to group members
        policy_name = sk.split("#")[-1]
        items = myiam.describe_group(ddbt, group_name)
        user_items = [item for item in items if item["sk"].startswith("user#")]
        user_names = [item["sk"].split("#")[-1] for item in user_items]
        for user_name in user_names:
            myiam.update_user_inherit_group_policies(ddbt, user_name, group_name, [policy_name])
            derived.append((group_name, user_name, policy_name))

    return derived


def _cleanup_user_group_policy_inheritance(record):
    pk, sk = _get_pk_sk(record)
    group_name = pk.split("#")[-1]
    is_user_sk = sk.startswith("user#")
    is_policy_sk = sk.startswith("policy#")
    cleaned = []

    # NOTE: this query+update sequence creates a race condition with other processes
    # adding or removing policies to the group at this time, and may result in users
    # with missing policies or unexpected policies.

    if is_user_sk:
        # When a group member is removed, detach inherited policies from it
        user_name = sk.split("#")[-1]
        items = myiam.describe_group(ddbt, group_name)
        policy_items = [item for item in items if item["sk"].startswith("policy#")]
        policy_names = [item["sk"].split("#")[-1] for item in policy_items]
        for policy_name in policy_names:
            myiam.update_user_disinherit_group_policies(ddbt, user_name, group_name, [policy_name])
            cleaned.append((group_name, user_name, policy_name))

    if is_policy_sk:
        # When a policy is removed from a group, detach it from group members
        policy_name = sk.split("#")[-1]
        items = myiam.describe_group(ddbt, group_name)
        user_items = [item for item in items if item["sk"].startswith("user#")]
        user_names = [item["sk"].split("#")[-1] for item in user_items]
        for user_name in user_names:
            myiam.update_user_disinherit_group_policies(ddbt, user_name, group_name, [policy_name])
            cleaned.append((group_name, user_name, policy_name))

    return cleaned


def _get_pk_sk(record):
    pk = record["dynamodb"]["Keys"].get("pk").get("S", "")
    sk = record["dynamodb"]["Keys"].get("sk").get("S", "")
    return pk, sk
