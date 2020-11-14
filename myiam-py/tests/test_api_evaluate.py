import pytest
from myiam import create_rule
from myiam import (
    create_user,
    create_role,
    create_policy,
    create_route_domain,
    create_route,
    update_role_attach_policies,
    update_user_attach_policies,
    find_action_name_from_access_request,
    find_policy_names_matching_user,
    find_policy_names_matching_role,
    find_evaluation_rules,
    calculate_allowance,
)


def test_find_action_name_from_access_request(ddbt):
    create_route_domain(ddbt, "myiam", description="MyIAM API action routes")
    create_route(ddbt, "myiam", "GET:/myiam/list_users", "myiam:ListUsers")
    create_route(ddbt, "myiam", "GET:/myiam/describe_user", "myiam:DescribeUser")
    http_request_data = {"http_method": "GET", "http_path": "/myiam/describe_user"}
    action_name = find_action_name_from_access_request(ddbt, http_request_data)
    assert action_name == "myiam:DescribeUser"
    http_request_data = {"http_method": "GET", "http_path": "/myiam/unknown_operation"}
    action_name = find_action_name_from_access_request(ddbt, http_request_data)
    assert action_name is None


def test_find_policy_names_matching_user(ddbt, generic_policy):
    create_user(ddbt, user_name="joe")
    create_user(ddbt, user_name="ann")
    create_policy(ddbt, policy_name="PolicyU", **generic_policy)
    create_policy(ddbt, policy_name="PolicyX", **generic_policy)
    create_policy(ddbt, policy_name="PolicyY", **generic_policy)
    create_policy(ddbt, policy_name="PolicyZ", **generic_policy)
    update_user_attach_policies(ddbt, "joe", policy_names=["PolicyU", "PolicyZ"])
    update_user_attach_policies(ddbt, "ann", policy_names=["PolicyY"])
    policies = find_policy_names_matching_user(ddbt, "joe")
    assert policies == ["PolicyU", "PolicyZ"]
    policies = find_policy_names_matching_user(ddbt, "ann")
    assert policies == ["PolicyY"]


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
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "002", "db:FetchCells", "allow")
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "003", "db:FetchSecret", "deny")
    create_rule(ddbt, "PolicyB", "ReadOnlyAccess", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyC", "ReadOnlyAccess", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyC", "*", "001", "db:FetchRows", "allow")
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
