from myiam import (
    list_policies,
    create_policy,
    describe_policy,
    update_policy_create_version,
    update_policy_set_default_version,
    update_policy_control,
    # delete_policy_version,
    delete_policy,
)


def test_create_policy(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    create_policy(ddbt, policy_name="SalesDataReadWrite", **generic_policy)
    policies = list_policies(ddbt)
    print(policies)


def test_update_policy_create_version(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    update_policy_create_version(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)


def test_update_policy_set_default_version(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    update_policy_create_version(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    update_policy_create_version(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    update_policy_set_default_version(ddbt, policy_name="SalesDataReadOnly", policy_version=3)
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)


def test_describe_policy(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)


def test_update_policy_control(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    update_policy_set_default_version(ddbt, policy_name="SalesDataReadOnly", policy_version=1)
    update_policy_control(ddbt, policy_name="SalesDataReadOnly", rules_version=1)
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)


def test_delete_policy(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    delete_policy(ddbt, policy_name="SalesDataReadOnly")
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)
