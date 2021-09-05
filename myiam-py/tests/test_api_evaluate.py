import pytest
import fnmatch
from myiam import create_rule
from myiam import (
    create_user,
    create_group,
    create_role,
    create_policy,
    describe_policy,
    convert_policy_statement_into_rules,
    update_group_add_users,
    update_role_attach_policies,
    update_user_attach_policies,
    update_user_inherit_group_policies,
    find_policy_names_matching_user,
    find_policy_names_matching_role,
    find_evaluation_rules,
    calculate_allowance,
)


def test_find_policy_names_matching_user(ddbt, generic_policy):
    create_user(ddbt, user_name="joe")
    create_user(ddbt, user_name="ann")
    create_group(ddbt, group_name="GroupA")
    update_group_add_users(ddbt, group_name="GroupA", user_names=["joe"])
    create_policy(ddbt, policy_name="PolicyU", **generic_policy)
    create_policy(ddbt, policy_name="PolicyX", **generic_policy)
    create_policy(ddbt, policy_name="PolicyY", **generic_policy)
    create_policy(ddbt, policy_name="PolicyZ", **generic_policy)
    create_policy(ddbt, policy_name="PolicyI", **generic_policy)
    update_user_attach_policies(ddbt, "joe", policy_names=["PolicyU", "PolicyZ"])
    update_user_inherit_group_policies(ddbt, "joe", group_name="GroupA", policy_names=["PolicyI"])
    update_user_attach_policies(ddbt, "ann", policy_names=["PolicyY"])
    assert find_policy_names_matching_user(ddbt, "joe") == ["PolicyI", "PolicyU", "PolicyZ"]
    assert find_policy_names_matching_user(ddbt, "ann") == ["PolicyY"]


def test_find_policy_names_matching_role(ddbt, generic_policy):
    create_role(ddbt, role_name="admin")
    create_role(ddbt, role_name="sales")
    create_policy(ddbt, policy_name="PolicyU", **generic_policy)
    create_policy(ddbt, policy_name="PolicyX", **generic_policy)
    create_policy(ddbt, policy_name="PolicyY", **generic_policy)
    create_policy(ddbt, policy_name="PolicyZ", **generic_policy)
    update_role_attach_policies(ddbt, "admin", policy_names=["PolicyX"])
    update_role_attach_policies(ddbt, "sales", policy_names=["PolicyY", "PolicyZ"])
    policies = find_policy_names_matching_role(ddbt, "admin")
    assert policies == ["PolicyX"]
    policies = find_policy_names_matching_role(ddbt, "sales")
    assert policies == ["PolicyY", "PolicyZ"]


def test_find_matching_rules(ddbt):
    create_rule(
        ddbt,
        "PolicyA",
        "ReadOnlyAccess",
        "md5:bdacec346a79ffd3b03024701ea9c354",
        "001",
        "db:FetchRows",
        "allow",
    )
    create_rule(
        ddbt,
        "PolicyA",
        "ReadOnlyAccess",
        "md5:bdacec346a79ffd3b03024701ea9c354",
        "002",
        "db:FetchCells",
        "allow",
    )
    create_rule(
        ddbt,
        "PolicyA",
        "ReadOnlyAccess",
        "md5:bdacec346a79ffd3b03024701ea9c354",
        "003",
        "db:FetchSecret",
        "deny",
    )
    create_rule(
        ddbt,
        "PolicyB",
        "ReadOnlyAccess",
        "md5:e674b05fe5c165efb9ed2bf0618bf40d",
        "001",
        "db:FetchRows",
        "allow",
    )
    create_rule(ddbt, "PolicyC", "ReadOnlyAccess", "-", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyC", "*", "-", "001", "db:FetchRows", "allow")
    rules = find_evaluation_rules(ddbt, "db:FetchRows", "database/1", ["PolicyA", "PolicyB"], {})
    print(rules)


@pytest.mark.parametrize(
    "policy,query,expected",
    [
        pytest.param(
            {
                "policy_name": "PolicyA",
                "statements": [
                    {
                        "sid": "1",
                        "effect": "Allow",
                        "actions": "db:FetchRows",
                        "resources": "database/1",
                    }
                ],
            },
            {
                "action_name": "db:FetchRows",
                "resource_name": "database/1",
                "policy_names": ["PolicyA"],
                "context": {},
            },
            [
                {
                    "pk": "policy#PolicyA",
                    "sk": "sid#1#0",
                    "rule_effect": "Allow",
                    "rule_action": "db:FetchRows",
                    "rule_resource_spec": "database/1",
                    "rule_condition": None,
                }
            ],
            id="PolicyA-singleaction-singleresource",
        ),
        pytest.param(
            {
                "policy_name": "PolicyB",
                "statements": [
                    {
                        "sid": "1",
                        "effect": "Allow",
                        "actions": "db:FetchRows",
                        "resources": ["database/1", "database/2"],
                    }
                ],
            },
            {
                "action_name": "db:FetchRows",
                "resource_name": "database/1",
                "policy_names": ["PolicyB"],
                "context": {},
            },
            [
                {
                    "pk": "policy#PolicyB",
                    "sk": "sid#1#0",
                    "rule_effect": "Allow",
                    "rule_action": "db:FetchRows",
                    "rule_resource_spec": "database/1",
                    "rule_condition": None,
                }
            ],
            id="PolicyB-singleaction-manyresources",
        ),
        pytest.param(
            {
                "policy_name": "PolicyC",
                "statements": [
                    {
                        "sid": "1",
                        "effect": "Allow",
                        "actions": ["db:FetchRows", "db:UpdateRows"],
                        "resources": "database/1",
                    }
                ],
            },
            {
                "action_name": "db:FetchRows",
                "resource_name": "database/1",
                "policy_names": ["PolicyC"],
                "context": {},
            },
            [
                {
                    "pk": "policy#PolicyC",
                    "sk": "sid#1#0",
                    "rule_effect": "Allow",
                    "rule_action": "db:FetchRows",
                    "rule_resource_spec": "database/1",
                    "rule_condition": None,
                }
            ],
            id="PolicyC-manyactions-singleresource",
        ),
        pytest.param(
            {
                "policy_name": "PolicyD",
                "statements": [
                    {
                        "sid": "1",
                        "effect": "Allow",
                        "actions": ["db:FetchRows", "db:UpdateRows"],
                        "resources": ["database/1", "database/2"],
                    },
                    {
                        "sid": "2",
                        "effect": "Allow",
                        "actions": "db:CreateRows",
                        "resources": "*",
                    },
                ],
            },
            {
                "action_name": "db:FetchRows",
                "resource_name": "database/1",
                "policy_names": ["PolicyD"],
                "context": {},
            },
            [
                {
                    "pk": "policy#PolicyD",
                    "sk": "sid#1#0",
                    "rule_effect": "Allow",
                    "rule_action": "db:FetchRows",
                    "rule_resource_spec": "database/1",
                    "rule_condition": None,
                }
            ],
            id="PolicyD-manyactions-manyresources",
        ),
        pytest.param(
            {
                "policy_name": "PolicyE",
                "statements": [
                    {
                        "sid": "1",
                        "effect": "Allow",
                        "actions": ["db:FetchRows", "db:UpdateRows"],
                        "resources": ["database/1", "database/2"],
                    },
                    {
                        "sid": "2",
                        "effect": "Allow",
                        "actions": "db:FetchRows",
                        "resources": "*",
                    },
                ],
            },
            {
                "action_name": "db:FetchRows",
                "resource_name": "database/1",
                "policy_names": ["PolicyE"],
                "context": {},
            },
            [
                {
                    "pk": "policy#PolicyE",
                    "sk": "sid#1#0",
                    "rule_effect": "Allow",
                    "rule_action": "db:FetchRows",
                    "rule_resource_spec": "database/1",
                    "rule_condition": None,
                },
                {
                    "pk": "policy#PolicyE",
                    "sk": "sid#2#0",
                    "rule_effect": "Allow",
                    "rule_action": "db:FetchRows",
                    "rule_resource_spec": "*",
                    "rule_condition": None,
                },
            ],
            id="PolicyE-manysid-manyrules",
        ),
    ],
)
def test_find_evaluation_rules(ddbt, policy, query, expected):

    # Create policy and derive rules to populate the evaluation index.
    create_policy(ddbt, **policy)
    items = describe_policy(ddbt, policy["policy_name"])
    for item in [_ for _ in items if _["sk"].startswith("sid")]:
        for rule in convert_policy_statement_into_rules(item):
            create_rule(ddbt, **rule)

    # Exercise the target function.
    found = find_evaluation_rules(ddbt, **query)

    # Normalize the outcome to simplify assertions.
    found = [{k: _[k] for k in set(tuple(_)) - {"statement_signature"}} for _ in found]

    # Verify that the correct evaluations rules were found.
    assert expected == found


@pytest.mark.parametrize(
    "resource,pattern,result",
    [
        ("domain:objs/rs-1", "*", True),
        ("domain:objs/rs-1", "*:*", True),
        ("domain:objs/rs-1", "*:objs/*", True),
        ("domain:objs/rs-1", "*:objs/rs-1", True),
        ("domain:objs/rs-1", "domain:*", True),
        ("domain:objs/rs-1", "domain:objs/*", True),
        ("domain:objs/rs-1", "domain:objs/rs-1", True),
        ("domain:objs/rs-1", "domain:objs/rs-2", False),
        ("domain:objs/rs-1", "domain:objs/????", True),
        ("domain:objs/rs-1", "domain:objs/??-?", True),
        ("domain:objs/rs-1", "domain:objs/*-?", True),
        ("domain:objs/rs-1", "domain:objs/rs*", True),
        ("domain:objs/rs-1", "domain:objs/rs-*", True),
        ("domain:objs/rs-1", "domain:objs/rs-?", True),
        ("domain:objs/rs-1", "domain:objs/?", False),
        ("domain:objs/rs-1", "domain:objs/?????", False),
        ("domain:objs/path/rs-1", "domain:objs/*", True),
        ("domain:objs/path/rs-1", "domain:objs/*/*", True),
        ("domain:objs/path/rs-1", "domain:objs/*/rs-*", True),
        ("domain:objs/path/rs-1", "domain:objs/*/??-*", True),
        ("domain:objs/path/rs-1", "domain:objs/path/*", True),
        ("domain:objs/path/rs-1", "domain:objs/path/rs-*", True),
        ("domain:objs/path/rs-1", "domain:objs/path/??-*", True),
        ("domain:objs/path/path/rs-1", "domain:objs/*/rs-*", True),
        ("domain:objs/path/path/rs-1", "domain:objs/path/*/rs-*", True),
    ],
)
# TODO: improve this test to target find_evaluation_rules instead
def test_matches_resource_name(resource, pattern, result):
    assert fnmatch.fnmatch(resource, pattern) == result


@pytest.mark.parametrize(
    "effects,result",
    [
        ([], "deny_implicit"),
        (["deny"], "deny_explicit"),
        (["deny", "deny"], "deny_explicit"),
        (["allow", "deny"], "deny_explicit"),
        (["deny", "allow"], "deny_explicit"),
        (["deny", "allow", "allow"], "deny_explicit"),
        (["allow"], "allow"),
        (["allow", "allow"], "allow"),
    ],
)
def test_calculate_allowance(ddbt, effects, result):
    assert calculate_allowance(ddbt, effects) == result
