from myiam import (
    list_roles,
    create_role,
    describe_role,
    update_role,
    update_role_attach_policies,
    update_role_detach_policies,
    update_role_trust_policy,
    # update_role_permission_boundary,
    # update_role_create_tag,
    # update_role_update_tag,
    # update_role_delete_tag,
    delete_role,
)


def test_create_role(ddbt):
    create_role(ddbt, role_name="engineer", human_name="Engineer")
    roles = list_roles(ddbt,)
    print(roles)


def test_describe_role(ddbt):
    create_role(ddbt, role_name="engineer", human_name="Engineer")
    role = describe_role(ddbt, role_name="engineer")
    print(role)


def test_update_role(ddbt):
    create_role(ddbt, role_name="engineer", human_name="Engineer")
    update_role(ddbt, role_name="engineer", human_name="DevelopmentEngineer")
    role = describe_role(ddbt, role_name="engineer")
    print(role)


def test_update_role_attach_policies(ddbt):
    create_role(ddbt, role_name="engineer", human_name="Engineer")
    update_role_attach_policies(ddbt, role_name="engineer", policy_names=["ManageUsersReadOnly"])
    role = describe_role(ddbt, role_name="engineer")
    print(role)


def test_update_role_detach_policies(ddbt):
    create_role(ddbt, role_name="engineer", human_name="Engineer")
    update_role_attach_policies(
        ddbt, role_name="engineer", policy_names=["ManageUsersReadOnly", "ManageDataAdmin"],
    )
    update_role_detach_policies(
        ddbt, role_name="engineer", policy_names=["ManageUsersReadOnly", "ManageDataAdmin"],
    )
    role = describe_role(ddbt, role_name="engineer")
    print(role)


def test_update_role_trust_policy(ddbt):
    create_role(ddbt, role_name="engineer", human_name="Engineer")
    update_role_trust_policy(
        ddbt,
        role_name="engineer",
        policy_attrs={"statements": [{"effect": "allow", "resources": ["*"], "actions": ["*"]}]},
    )
    role = describe_role(ddbt, role_name="engineer")
    print(role)


def test_delete_role(ddbt):
    create_role(ddbt, role_name="engineering", human_name="Engineering")
    delete_role(ddbt, role_name="engineering")
    role = describe_role(ddbt, role_name="engineering")
    print(role)
