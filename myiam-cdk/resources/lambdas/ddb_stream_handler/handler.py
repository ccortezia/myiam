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

        if _should_sync_policy_statement_rules(record):
            new_rules, old_rules = _sync_policy_statement_rules(record)
            logger.info(json.dumps({"event": "RULES_CREATED", "rules": new_rules}))
            logger.info(json.dumps({"event": "RULES_REMOVED", "rules": old_rules}))


def _should_sync_policy_statement_rules(record):

    if record["eventName"] != "MODIFY":
        return False

    pk, sk = _get_pk_sk(record)
    is_policy_pk = pk.startswith("policy#")
    is_policy_control = sk == "policy#control"
    new_version = record["dynamodb"]["NewImage"]["default_version"]["N"]
    old_version = record["dynamodb"]["OldImage"]["default_version"]["N"]
    default_policy_version_changed = new_version != old_version

    return is_policy_pk and is_policy_control and default_policy_version_changed


def _sync_policy_statement_rules(record):

    new_rules = []
    old_rules = []

    pk, sk = _get_pk_sk(record)
    policy_name = pk.split("#")[-1]
    old_version = record["dynamodb"]["OldImage"]["default_version"]["N"]
    new_version = record["dynamodb"]["NewImage"]["default_version"]["N"]

    # TODO: research whether forced consistency must be used in this query, to avoid
    # inconsistency in case this operation is performed too soon after the version update.
    items = myiam.describe_policy(ddbt, policy_name=policy_name)

    for policy_item in items:

        # Ignore statement ids of policy versions that are not the latest default.
        if not policy_item["sk"].startswith(f"sid@{new_version}"):
            continue

        # Convert statement into rules
        new_rules = myiam.convert_policy_statement_into_rules(
            {
                "pk": policy_item["pk"],
                "sk": policy_item["sk"],
                "effect": policy_item["effect"],
                "resources":  policy_item["resources"],
                "actions":  policy_item["actions"],
            }
        )

        # Insert new rules for statement
        for rule in new_rules:
            # TODO: handle ddbt.meta.client.exceptions.ConditionalCheckFailedException for
            # uniqueness failures, to avoid crashing the streaming Lambda.
            myiam.create_rule(ddbt, **rule)

    # Set a flag to indicate the rules have been updated to match the latest version.
    myiam.update_policy_control(ddbt, policy_name, rules_version=new_version)

    # Cleanup deactivated rules respective to the deactivated policy version.
    old_rules = myiam.delete_rules_by_policy_version(ddbt, policy_name, old_version)

    return new_rules, old_rules


def _cleanup_policy_statement_rules(record):
    pk, sk = _get_pk_sk(record)
    policy_name = pk.split("#")[-1]
    old_version = record["dynamodb"]["OldImage"].get("default_version", {})["N"]
    rules = myiam.delete_rules_by_policy_version(ddbt, policy_name, old_version)
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
