from myiam.api import (
    list_users,
    create_user,
    describe_user,
    update_user,
    update_user_add_to_groups,
    update_user_remove_from_groups,
    update_user_attach_policies,
    update_user_detach_policies,
    # update_user_create_tag,
    # update_user_update_tag,
    # update_user_delete_tag,
    delete_user,
)


def test_create_user(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    users = list_users(ddbt)
    print(users)


def test_describe_user(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    user = describe_user(ddbt, user_name="joe")
    print(user)


def test_update_user(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    update_user(ddbt, user_name="joe", human_name="joseph")
    user = describe_user(ddbt, user_name="joe")
    print(user)


def test_update_user_add_to_groups(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    update_user_add_to_groups(ddbt, user_name="joe", group_names=["admin", "sales"])
    user = describe_user(ddbt, user_name="joe")
    print(user)


def test_update_user_remove_from_groups(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    update_user_add_to_groups(ddbt, user_name="joe", group_names=["admin", "sales"])
    update_user_remove_from_groups(ddbt, user_name="joe", group_names=["admin", "sales"])
    user = describe_user(ddbt, user_name="joe")
    print(user)


def test_update_user_attach_policies(ddbt):
    create_user(ddbt, user_name="engineer", human_name="Engineer")
    update_user_attach_policies(ddbt, user_name="engineer", policy_names=["ManageUsersReadOnly"])
    user = describe_user(ddbt, user_name="engineer")
    print(user)


def test_update_user_detach_policies(ddbt):
    create_user(ddbt, user_name="engineer", human_name="Engineer")
    update_user_attach_policies(
        ddbt, user_name="engineer", policy_names=["ManageUsersReadOnly", "ManageDataAdmin"],
    )
    update_user_detach_policies(
        ddbt, user_name="engineer", policy_names=["ManageUsersReadOnly", "ManageDataAdmin"],
    )
    user = describe_user(ddbt, user_name="engineer")
    print(user)


def test_delete_user(ddbt):
    create_user(ddbt, user_name="joe", human_name="Joe")
    delete_user(ddbt, user_name="joe")
    user = describe_user(ddbt, user_name="joe")
    print(user)
