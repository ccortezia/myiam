from myiam import create_user

from myiam import (
    list_groups,
    create_group,
    describe_group,
    update_group,
    update_group_add_users,
    update_group_remove_users,
    # update_group_attach_policies,
    # update_group_detach_policies,
    # update_group_create_inline_policy,
    # update_group_update_inline_policy,
    # update_group_delete_inline_policy,
    delete_group,
)


def test_create_group(ddbt):
    create_group(ddbt, group_name="sales", human_name="Sales")
    groups = list_groups(ddbt,)
    print(groups)


def test_describe_group(ddbt):
    create_group(ddbt, group_name="sales", human_name="Sales")
    group = describe_group(ddbt, group_name="sales")
    print(group)


def test_update_group(ddbt):
    create_group(ddbt, group_name="sales", human_name="Sales")
    update_group(ddbt, group_name="sales", human_name="joseph")
    group = describe_group(ddbt, group_name="sales")
    print(group)


def test_update_group_add_users(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    create_user(ddbt, user_name="ann", human_name="Ann")
    create_group(ddbt, group_name="sales", human_name="Sales")
    update_group_add_users(ddbt, group_name="sales", user_names=["joe", "ann"])
    group = describe_group(ddbt, group_name="sales")
    print(group)


def test_update_group_remove_users(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    create_user(ddbt, user_name="ann", human_name="Ann")
    create_group(ddbt, group_name="sales", human_name="Sales")
    update_group_add_users(ddbt, group_name="sales", user_names=["joe", "ann"])
    update_group_remove_users(ddbt, group_name="sales", user_names=["joe", "ann"])
    group = describe_group(ddbt, group_name="sales")
    print(group)


def test_delete_group(ddbt):
    create_group(ddbt, group_name="sales", human_name="Sales")
    delete_group(ddbt, group_name="sales")
    group = describe_group(ddbt, group_name="sales")
    print(group)
