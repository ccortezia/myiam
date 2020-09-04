import pytest
from myiam import create_rule
from myiam import (
    create_user,
    create_role,
    create_policy,
    update_role_attach_policies,
    update_user_attach_policies,
    find_matching_rules,
    find_matching_policies,
    calculate_allowance,
)


@pytest.mark.skip
def test_find_matching_action(ddbt):
    # find_matching_action(table, access_context)
    pass


def test_find_matching_policies(ddbt, generic_policy):
    create_user(ddbt, user_name="joe")
    create_role(ddbt, role_name="admin")
    create_role(ddbt, role_name="sales")
    create_policy(ddbt, policy_name="PolicyU", **generic_policy)
    create_policy(ddbt, policy_name="PolicyX", **generic_policy)
    create_policy(ddbt, policy_name="PolicyY", **generic_policy)
    create_policy(ddbt, policy_name="PolicyZ", **generic_policy)
    update_user_attach_policies(ddbt, "joe", policy_names=["PolicyU", "PolicyZ"])
    update_role_attach_policies(ddbt, "admin", policy_names=["PolicyX"])
    update_role_attach_policies(ddbt, "sales", policy_names=["PolicyY", "PolicyZ"])
    policies = find_matching_policies(ddbt, "joe", "admin")
    print(policies)
    policies = find_matching_policies(ddbt, "joe", "sales")
    print(policies)
    pass


def test_find_matching_rules(ddbt):
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "002", "db:FetchCells", "allow")
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "003", "db:FetchSecret", "deny")
    create_rule(ddbt, "PolicyB", "ReadOnlyAccess", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyC", "ReadOnlyAccess", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyC", "*", "001", "db:FetchRows", "allow")
    rules = find_matching_rules(ddbt, "db:FetchRows", "database/1", ["PolicyA", "PolicyB"], {})
    print(rules)


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
