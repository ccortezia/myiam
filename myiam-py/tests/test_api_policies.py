from myiam import (
    list_policies,
    create_policy,
    describe_policy,
    # update_policy_set_default_version,
    # delete_policy_version,
    delete_policy,
)


def test_create_policy(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    policys = list_policies(ddbt)
    print(policys)


def test_create_multiaction_policy(ddbt, multiaction_policy):
    create_policy(ddbt, policy_name="SalesDataReadWrite", **multiaction_policy)
    policys = list_policies(ddbt)
    print(policys)


def test_describe_policy(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)


def test_delete_policy(ddbt, generic_policy):
    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)
    delete_policy(ddbt, policy_name="SalesDataReadOnly")
    policy = describe_policy(ddbt, policy_name="SalesDataReadOnly")
    print(policy)
