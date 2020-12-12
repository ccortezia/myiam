import myiam
import myiam_api


def list_users():
    records = myiam.list_users(myiam_api.app.table)
    return [{"username": record["pk"].split("#")[-1]} for record in records]


def create_user():
    return ("Procedure not yet supported", 404)


def describe_user():
    records = myiam.describe_user(myiam_api.app.table, "ccortezia")
    return [{"username": record["pk"].split("#")[-1]} for record in records]


def update_user():
    return ("Procedure not yet supported", 404)


def update_user_add_to_groups():
    return ("Procedure not yet supported", 404)


def update_user_remove_from_groups():
    return ("Procedure not yet supported", 404)


def update_user_attach_policies():
    return ("Procedure not yet supported", 404)


def update_user_detach_policies():
    return ("Procedure not yet supported", 404)


def update_user_create_tag():
    return ("Procedure not yet supported", 404)


def update_user_update_tag():
    return ("Procedure not yet supported", 404)


def update_user_delete_tag():
    return ("Procedure not yet supported", 404)


def delete_user():
    return ("Procedure not yet supported", 404)


def list_groups():
    return ("Procedure not yet supported", 404)


def create_group():
    return ("Procedure not yet supported", 404)


def describe_group():
    return ("Procedure not yet supported", 404)


def update_group():
    return ("Procedure not yet supported", 404)


def update_group_add_users():
    return ("Procedure not yet supported", 404)


def update_group_remove_users():
    return ("Procedure not yet supported", 404)


def update_group_attach_policies():
    return ("Procedure not yet supported", 404)


def update_group_detach_policies():
    return ("Procedure not yet supported", 404)


def update_group_create_inline_policy():
    return ("Procedure not yet supported", 404)


def update_group_update_inline_policy():
    return ("Procedure not yet supported", 404)


def update_group_delete_inline_policy():
    return ("Procedure not yet supported", 404)


def delete_group():
    return ("Procedure not yet supported", 404)


def list_roles():
    return ("Procedure not yet supported", 404)


def create_role():
    return ("Procedure not yet supported", 404)


def describe_role():
    return ("Procedure not yet supported", 404)


def update_role():
    return ("Procedure not yet supported", 404)


def update_role_attach_policies():
    return ("Procedure not yet supported", 404)


def update_role_detach_policies():
    return ("Procedure not yet supported", 404)


def update_role_trust_policy():
    return ("Procedure not yet supported", 404)


def update_role_permission_boundary():
    return ("Procedure not yet supported", 404)


def update_role_create_tag():
    return ("Procedure not yet supported", 404)


def update_role_update_tag():
    return ("Procedure not yet supported", 404)


def update_role_delete_tag():
    return ("Procedure not yet supported", 404)


def delete_role():
    return ("Procedure not yet supported", 404)


def list_policies():
    return ("Procedure not yet supported", 404)


def create_policy():
    return ("Procedure not yet supported", 404)


def describe_policy():
    return ("Procedure not yet supported", 404)


def update_policy_set_default_version():
    return ("Procedure not yet supported", 404)


def delete_policy_version():
    return ("Procedure not yet supported", 404)


def delete_policy():
    return ("Procedure not yet supported", 404)


def list_actions():
    return ("Procedure not yet supported", 404)


def create_action():
    return ("Procedure not yet supported", 404)


def describe_action():
    return ("Procedure not yet supported", 404)


def update_action():
    return ("Procedure not yet supported", 404)


def delete_action():
    return ("Procedure not yet supported", 404)


def list_resolvers():
    return myiam.list_resolvers(myiam_api.app.table)


def create_resolver():
    return ("Procedure not yet supported", 404)


def describe_resolver():
    return ("Procedure not yet supported", 404)


def delete_resolver():
    return ("Procedure not yet supported", 404)
