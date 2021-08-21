import pytest
from myiam import create_rule
from myiam import (
    create_user,
    create_group,
    create_role,
    create_policy,
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
