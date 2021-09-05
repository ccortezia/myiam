from operator import itemgetter
import functools
import fnmatch
import hashlib
import itertools
from boto3.dynamodb.conditions import Attr, Key

__all__ = (
    "list_users",
    "create_user",
    "describe_user",
    "update_user",
    "update_user_add_to_groups",
    "update_user_remove_from_groups",
    "update_user_attach_policies",
    "update_user_detach_policies",
    "update_user_inherit_group_policies",
    "update_user_disinherit_group_policies",
    "update_user_create_tag",
    "update_user_update_tag",
    "update_user_delete_tag",
    "delete_user",
    "list_groups",
    "create_group",
    "describe_group",
    "update_group",
    "update_group_add_users",
    "update_group_remove_users",
    "update_group_attach_policies",
    "update_group_detach_policies",
    "update_group_create_inline_policy",
    "update_group_update_inline_policy",
    "update_group_delete_inline_policy",
    "delete_group",
    "list_roles",
    "create_role",
    "describe_role",
    "update_role",
    "update_role_attach_policies",
    "update_role_detach_policies",
    "update_role_create_inline_policy",
    "update_role_update_inline_policy",
    "update_role_delete_inline_policy",
    "update_role_trust_policy",
    "update_role_permission_boundary",
    "update_role_create_tag",
    "update_role_update_tag",
    "update_role_delete_tag",
    "delete_role",
    "list_policies",
    "create_policy",
    "describe_policy",
    "update_policy_set_default_version",
    "delete_policy_version",
    "delete_policy",
    "list_actions",
    "create_action",
    "describe_action",
    "update_action",
    "delete_action",
    "list_resolvers",
    "create_resolver",
    "describe_resolver",
    "delete_resolver",
    "convert_policy_statement_into_rules",
    "create_rule",
    "describe_rule",
    "delete_rule",
    "delete_rules_by_sid",
    "find_policy_names_matching_user",
    "find_policy_names_matching_role",
    "find_evaluation_rules",
    "calculate_allowance",
)


# --------------------------------------------------------------------------------------------------
# USERS
# --------------------------------------------------------------------------------------------------


def list_users(table):
    response = table.scan(FilterExpression=Attr("pk").begins_with("user"))
    return response["Items"]


def create_user(table, user_name, **attrs):
    table.put_item(
        Item={"pk": f"user#{user_name}", "sk": "user#attributes", **attrs},
        ConditionExpression=Attr("pk").not_exists(),
    )


def describe_user(table, user_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"user#{user_name}"))
    return response.get("Items") or []


def update_user(table, user_name, **attrs):
    # NOTE: could use put_item here
    table.update_item(
        Key={"pk": f"user#{user_name}", "sk": "user#attributes"},
        AttributeUpdates={attr: {"Value": value, "Action": "PUT"} for attr, value in attrs.items()},
    )


def update_user_add_to_groups(table, user_name, group_names):
    # TODO: use write batch
    for group_name in group_names:
        table.put_item(Item={"pk": f"group#{group_name}", "sk": f"user#{user_name}"})


def update_user_remove_from_groups(table, user_name, group_names):
    # TODO: use write batch
    for group_name in group_names:
        table.delete_item(Key={"pk": f"group#{group_name}", "sk": f"user#{user_name}"})


def update_user_attach_policies(table, user_name, policy_names):
    for policy_name in policy_names:
        table.put_item(Item={"pk": f"user#{user_name}", "sk": f"policy#{policy_name}"})


def update_user_detach_policies(table, user_name, policy_names):
    with table.batch_writer() as batch:
        for policy_name in policy_names:
            batch.delete_item(
                Key={"pk": f"user#{user_name}", "sk": f"policy#user#self#{policy_name}"}
            )


def update_user_inherit_group_policies(table, user_name, group_name, policy_names):
    with table.batch_writer() as batch:
        for policy_name in policy_names:
            batch.put_item(
                Item={"pk": f"user#{user_name}", "sk": f"policy#group#{group_name}#{policy_name}"}
            )


def update_user_disinherit_group_policies(table, user_name, group_name, policy_names):
    with table.batch_writer() as batch:
        for policy_name in policy_names:
            batch.delete_item(
                Key={"pk": f"user#{user_name}", "sk": f"policy#group#{group_name}#{policy_name}"}
            )


def update_user_create_tag(table, user_name, tag_name, tag_attrs):
    raise NotImplementedError()


def update_user_update_tag(table, user_name, tag_name, tag_attrs):
    raise NotImplementedError()


def update_user_delete_tag(table, user_name, tag_name):
    raise NotImplementedError()


def delete_user(table, user_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"user#{user_name}"))
    with table.batch_writer() as batch:
        for pk, sk in [(item["pk"], item["sk"]) for item in response["Items"]]:
            batch.delete_item(Key={"pk": pk, "sk": sk})


# --------------------------------------------------------------------------------------------------
# GROUP
# --------------------------------------------------------------------------------------------------


def list_groups(table):
    response = table.scan(FilterExpression=Attr("pk").begins_with("group"))
    return response["Items"]


def create_group(table, group_name, **attrs):
    table.put_item(
        Item={"pk": f"group#{group_name}", "sk": "group#attributes", **attrs},
        ConditionExpression=Attr("pk").not_exists(),
    )


def describe_group(table, group_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"group#{group_name}"))
    return response.get("Items") or []


def update_group(table, group_name, **attrs):
    # NOTE: could use put_item here
    table.update_item(
        Key={"pk": f"group#{group_name}", "sk": "group#attributes"},
        AttributeUpdates={attr: {"Value": value, "Action": "PUT"} for attr, value in attrs.items()},
    )


def update_group_add_users(table, group_name, user_names):
    for user_name in user_names:
        table.put_item(Item={"pk": f"group#{group_name}", "sk": f"user#{user_name}"})


def update_group_remove_users(table, group_name, user_names):
    with table.batch_writer() as batch:
        for user_name in user_names:
            batch.delete_item(Key={"pk": f"group#{group_name}", "sk": f"user#{user_name}"})


def update_group_attach_policies(table, group_name, policy_names):
    with table.batch_writer() as batch:
        for policy_name in policy_names:
            batch.put_item(Item={"pk": f"group#{group_name}", "sk": f"policy#{policy_name}"})


def update_group_detach_policies(table, group_name, policy_names):
    with table.batch_writer() as batch:
        for policy_name in policy_names:
            batch.delete_item(Key={"pk": f"group#{group_name}", "sk": f"policy#{policy_name}"})


def update_group_create_inline_policy(table, group_name, policy_name, policy_attrs):
    raise NotImplementedError()


def update_group_update_inline_policy(table, group_name, policy_name, policy_attrs):
    raise NotImplementedError()


def update_group_delete_inline_policy(table, group_name, policy_name):
    raise NotImplementedError()


def delete_group(table, group_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"group#{group_name}"))
    with table.batch_writer() as batch:
        for pk, sk in [(item["pk"], item["sk"]) for item in response["Items"]]:
            batch.delete_item(Key={"pk": pk, "sk": sk})


# --------------------------------------------------------------------------------------------------
# ROLES
# --------------------------------------------------------------------------------------------------


def list_roles(table):
    response = table.scan(FilterExpression=Attr("pk").begins_with("role"))
    return response["Items"]


def create_role(table, role_name, **attrs):
    table.put_item(
        Item={"pk": f"role#{role_name}", "sk": "role#attributes", **attrs},
        ConditionExpression=Attr("pk").not_exists(),
    )


def describe_role(table, role_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"role#{role_name}"))
    return response.get("Items") or []


def update_role(table, role_name, **attrs):
    # NOTE: could use put_item here
    table.update_item(
        Key={"pk": f"role#{role_name}", "sk": "role#attributes"},
        AttributeUpdates={attr: {"Value": value, "Action": "PUT"} for attr, value in attrs.items()},
    )


def update_role_attach_policies(table, role_name, policy_names):
    for policy_name in policy_names:
        table.put_item(Item={"pk": f"role#{role_name}", "sk": f"policy#{policy_name}"})


def update_role_detach_policies(table, role_name, policy_names):
    with table.batch_writer() as batch:
        for policy_name in policy_names:
            batch.delete_item(Key={"pk": f"role#{role_name}", "sk": f"policy#{policy_name}"})


def update_role_create_inline_policy(table, role_name, policy_name, policy_attrs):
    raise NotImplementedError()


def update_role_update_inline_policy(table, role_name, policy_name, policy_attrs):
    raise NotImplementedError()


def update_role_delete_inline_policy(table, role_name, policy_name):
    raise NotImplementedError()


def update_role_trust_policy(table, role_name, policy_attrs):
    table.put_item(Item={"pk": f"role#{role_name}", "sk": "trust", **policy_attrs})


def update_role_permission_boundary(table, role_name, policy_name):
    raise NotImplementedError()


def update_role_create_tag(table, role_name, tag_name, tag_attrs):
    raise NotImplementedError()


def update_role_update_tag(table, role_name, tag_name, tag_attrs):
    raise NotImplementedError()


def update_role_delete_tag(table, role_name, tag_name):
    raise NotImplementedError()


def delete_role(table, role_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"role#{role_name}"))
    with table.batch_writer() as batch:
        for pk, sk in [(item["pk"], item["sk"]) for item in response["Items"]]:
            batch.delete_item(Key={"pk": pk, "sk": sk})


# --------------------------------------------------------------------------------------------------
# POLICIES
# --------------------------------------------------------------------------------------------------


def list_policies(table):
    response = table.scan(FilterExpression=Attr("pk").begins_with("policy"))
    return response["Items"]


def _make_policy_item_signatures(policy_name, statements):

    # Derive rules eagerly to check policy sanity and to support signature calculation.
    rules = []
    for statement in statements:
        rules.extend(_make_rules_from_policy_statement(policy_name, **statement))
    rules = sorted(rules, key=itemgetter("action_name"))

    statement_signatures = {}
    for action_name, _rules in itertools.groupby(rules, key=itemgetter("action_name")):
        items = [
            {"pk": f"policy#{_rule['policy_name']}", "sk": f"sid#{_rule['statement_id']}"}
            for _rule in _rules
        ]
        statement_signatures[action_name] = _calculate_items_signature(items)

    return statement_signatures


def create_policy(table, policy_name, statements, **attrs):

    # Calculates the item signature map to support propagating decomposed statements.
    # Since decomposed statements are not all made available for evaluation at the
    # same time, these signatures are used for integrity check during evaluation.
    # In practice, until all of the statement pieces for a policy are available in the
    # evaluation index, then none of them is considered for evaluation.
    #
    # Example Signature Map: {
    #     "Action1": "md5:b86a468a5158487d1caec83601f32b97",
    #     "Action2": "md5:1b36624db86b5aae71102626d1941508"
    # }
    statement_signatures = _make_policy_item_signatures(policy_name, statements)

    # Calculates statement items from input.
    st_items = [
        {
            "pk": f"policy#{policy_name}",
            "sk": f"sid#{st['sid']}",
            "effect": st["effect"],
            "resources": st["resources"],
            "actions": st["actions"],
        }
        for st in statements
    ]

    # Augment statement items with statement-relevant signatures.
    for st_item in st_items:
        actions = st_item["actions"]
        st_item_actions = {actions} if isinstance(actions, str) else set(actions)
        st_item["statement_signatures"] = {
            action: signature
            for action, signature in statement_signatures.items()
            if action in st_item_actions
        }

    # Persist statement items.
    for st_item in st_items:
        table.put_item(Item=st_item)

    # Persist policy attributes.
    table.put_item(
        Item={"pk": f"policy#{policy_name}", "sk": "policy#attributes", **attrs},
        ConditionExpression=Attr("pk").not_exists(),
    )


def describe_policy(table, policy_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"policy#{policy_name}"))
    return response.get("Items") or []


def update_policy_set_default_version(table, policy_name, version_number):
    # TODO: need to learn how to properly implement versioning
    raise NotImplementedError()


def delete_policy_version(table, policy_name, version_number):
    # TODO: need to learn how to properly implement versioning
    raise NotImplementedError()


def delete_policy(table, policy_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"policy#{policy_name}"))
    with table.batch_writer() as batch:
        for pk, sk in [(item["pk"], item["sk"]) for item in response["Items"]]:
            batch.delete_item(Key={"pk": pk, "sk": sk})


# --------------------------------------------------------------------------------------------------
# ACTIONS
# --------------------------------------------------------------------------------------------------


def list_actions(table):
    response = table.scan(FilterExpression=Attr("pk").begins_with("action"))
    return response["Items"]


def create_action(table, action_name, **attrs):
    table.put_item(
        Item={"pk": f"action#{action_name}", "sk": "action#attributes", **attrs},
        ConditionExpression=Attr("pk").not_exists(),
    )


def describe_action(table, action_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"action#{action_name}"))
    return response.get("Items") or []


def update_action(table, action_name, **attrs):
    # TODO: need to learn how to properly implement versioning
    # NOTE: could use put_item here
    table.update_item(
        Key={"pk": f"action#{action_name}", "sk": "action#attributes"},
        AttributeUpdates={attr: {"Value": value, "Action": "PUT"} for attr, value in attrs.items()},
    )


def delete_action(table, action_name):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"action#{action_name}"))
    with table.batch_writer() as batch:
        for pk, sk in [(item["pk"], item["sk"]) for item in response["Items"]]:
            batch.delete_item(Key={"pk": pk, "sk": sk})


# --------------------------------------------------------------------------------------------------
# RESOLVERS
# --------------------------------------------------------------------------------------------------


def list_resolvers(table):
    response = table.scan(FilterExpression=Attr("pk").begins_with("resolver#"))
    return response["Items"]


def create_resolver(table, request_key, action, resource):
    table.put_item(
        Item={
            "pk": f"resolver#{request_key}",
            "sk": "resolver#mapping",
            "resource": resource,
            "action": action,
        },
        ConditionExpression=Attr("pk").not_exists() & Attr("sk").not_exists(),
    )


def describe_resolver(table, request_key):
    response = table.query(KeyConditionExpression=Key("pk").eq(f"resolver#{request_key}"))
    return response.get("Items") or []


def delete_resolver(table, request_key):
    table.delete_item(Key={"pk": f"resolver#{request_key}", "sk": "resolver#mapping"})


# --------------------------------------------------------------------------------------------------
# RULES
# --------------------------------------------------------------------------------------------------


def _make_rules_from_policy_statement(policy_name, sid, effect, actions, resources):
    rules = []

    actions = [actions] if isinstance(actions, str) else actions
    resources = [resources] if isinstance(resources, str) else resources

    # TODO: expand actions * wildcard from domain's action definitions
    product = itertools.product(actions, resources)

    for rule_id, (action_name, resource_spec) in enumerate(product):
        # TODO: filter product according to action definitions
        #  to avoid creating rules for an action without resource correspondence.
        rules.append(
            {
                "rule_id": str(rule_id),
                "action_name": action_name,
                "resource_spec": resource_spec,
                "policy_name": policy_name,
                "statement_id": sid,
                "effect": effect,
                "condition": None,
            }
        )

    return rules


def convert_policy_statement_into_rules(statement_item):

    # TODO: move these two steps into an "item-decoding" layer
    policy_name = statement_item["pk"].split("#")[1]
    sid = statement_item["sk"].split("#")[1]

    rules = _make_rules_from_policy_statement(
        policy_name=policy_name,
        sid=sid,
        effect=statement_item["effect"],
        actions=statement_item["actions"],
        resources=statement_item["resources"],
    )

    # Sign rules to enable later statement integrity verification.
    for rule in rules:
        action_name = rule["action_name"]
        statement_signatures = statement_item["statement_signatures"]
        rule["statement_signature"] = statement_signatures[action_name]

    return rules


def create_rule(
    table,
    policy_name,
    statement_id,
    statement_signature,
    rule_id,
    action_name,
    effect,
    resource_spec="*",
    condition=None,
):
    table.put_item(
        Item={
            "pk": f"policy#{policy_name}",
            "sk": f"sid#{statement_id}#{rule_id}",
            "rule_action": action_name,
            "rule_effect": effect,
            "rule_resource_spec": resource_spec,
            "rule_condition": None,
            "statement_signature": statement_signature,
        },
        ConditionExpression=Attr("pk").not_exists(),
    )


def describe_rule(table, policy_name, statement_id, rule_id):
    response = table.query(
        KeyConditionExpression=Key("pk").eq(f"policy#{policy_name}")
        & Key("sk").eq(f"sid#{statement_id}#{rule_id}")
    )
    return response.get("Items") or []


def delete_rules_by_sid(table, policy_name, statement_id):
    response = table.query(
        KeyConditionExpression=Key("pk").eq(f"policy#{policy_name}")
        & Key("sk").begins_with(f"sid#{statement_id}#")
    )
    rules = response.get("Items") or []
    with table.batch_writer() as batch:
        for rule in rules:
            batch.delete_item(Key={"pk": rule["pk"], "sk": rule["sk"]})
    return rules


def delete_rule(table, policy_name, statement_id, rule_id):
    table.delete_item(Key={"pk": f"policy#{policy_name}", "sk": f"sid#{statement_id}#{rule_id}"})


# --------------------------------------------------------------------------------------------------
# EVALUATION
# --------------------------------------------------------------------------------------------------


def find_policy_names_matching_user(table, user):
    result = table.query(KeyConditionExpression=Key("pk").eq(f"user#{user}"))
    user_policies = result["Items"]
    policies = [
        item["sk"].split("#")[-1] for item in user_policies if item["sk"].startswith("policy#")
    ]
    return sorted(set(policies))


def find_policy_names_matching_role(table, role):
    result = table.query(KeyConditionExpression=Key("pk").eq(f"role#{role}"))
    role_policies = result["Items"]
    policies = [
        item["sk"].split("#")[1] for item in role_policies if item["sk"].startswith("policy#")
    ]
    return sorted(set(policies))


def find_evaluation_rules(table, action_name, resource_name, policy_names, context):
    def _matches_predicate(item, context):
        predicate_fn = item["rule_condition"]
        if not predicate_fn:
            return True
        # predicate_fn is a pre-compiled cached Python function
        # TODO: decompile predicate_fn into callable code
        # TODO: return predicate_fn(context)
        return True

    policy_keys = [f"policy#{policy_name}" for policy_name in policy_names]

    # Find applicable rules from input action.
    result = table.query(
        IndexName="action_lookup",
        KeyConditionExpression=Key("rule_action").eq(action_name),
        FilterExpression=Attr("pk").is_in(policy_keys),
    )
    action_scoped_items = result["Items"]

    result = table.query(
        IndexName="action_lookup",
        KeyConditionExpression=Key("rule_action").eq("*"),
        FilterExpression=Attr("pk").is_in(policy_keys),
    )
    wildcard_unscoped_items = result["Items"]

    fetched_rules = action_scoped_items + wildcard_unscoped_items

    rules = []

    # Validate rule-set integrity by matching propagated policy statement signatures.
    fetched_rules = sorted(fetched_rules, key=itemgetter("pk"))
    for policy_pk, ruleset in itertools.groupby(fetched_rules, key=itemgetter("pk")):
        ruleset = list(ruleset)
        items = [{"pk": rule["pk"], "sk": "#".join(rule["sk"].split("#")[:2])} for rule in ruleset]
        signature = _calculate_items_signature(items)
        _rules = [rule for rule in ruleset if signature == rule["statement_signature"]]
        rules.extend(_rules)

    resource_matcher = functools.partial(fnmatch.fnmatch, resource_name)

    rules = [item for item in rules if resource_matcher(item["rule_resource_spec"])]
    rules = [item for item in rules if _matches_predicate(item, context)]

    return rules


def _calculate_items_signature(items):
    signature = hashlib.md5()
    for item in sorted(items, key=itemgetter("pk", "sk")):
        signature.update("{pk}/{sk}".format(**item).encode("utf8"))
    return f"md5:{signature.hexdigest()}"


def calculate_allowance(table, effects):
    allowance_found = False
    for effect in effects:
        if effect == "deny":
            return "deny_explicit"
        if effect == "allow":
            allowance_found = True
    if allowance_found:
        return "allow"
    return "deny_implicit"
