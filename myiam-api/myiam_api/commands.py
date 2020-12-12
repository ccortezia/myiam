import yaml
import pathlib
import logging
import myiam_api
import myiam


HERE = pathlib.Path(__file__).parent


@myiam_api.app.cli.command("reset-resolvers")
def reset_resolvers():
    logger = logging.getLogger("myiam_api").getChild("cli")

    items = myiam.list_resolvers(table=myiam_api.app.table)
    for item in items:
        request_key = item["pk"].split("#")[-1]
        logger.info(f"Deleting resolver {request_key}")
        myiam.delete_resolver(table=myiam_api.app.table, request_key=request_key)

    with open(HERE / "data/resolvers.yaml") as fp:
        resolvers = yaml.safe_load(fp.read())

    for resolver in resolvers:
        logger.info("Setting resolver {request_key} => {action}".format(**resolver))
        myiam.create_resolver(
            table=myiam_api.app.table,
            request_key=resolver["request_key"],
            resource=resolver["resource"],
            action=resolver["action"],
        )


@myiam_api.app.cli.command("reset-policies")
def reset_policies():
    logger = logging.getLogger("myiam_api").getChild("cli")

    with open(HERE / "data/policies.yaml") as fp:
        source_policies = yaml.safe_load(fp.read())

    policies = myiam.list_policies(table=myiam_api.app.table)
    for policy in policies:
        policy_name = policy["pk"].split("#")[-1]
        myiam.delete_policy(table=myiam_api.app.table, policy_name=policy_name)

    for item in source_policies:
        logger.info(item["policy_name"])
        myiam.create_policy(
            table=myiam_api.app.table,
            policy_name=item["policy_name"],
            statements=item["statements"],
        )


@myiam_api.app.cli.command("reset-roles")
def reset_roles():
    logger = logging.getLogger("myiam_api").getChild("cli")

    with open(HERE / "data/roles.yaml") as fp:
        source_roles = yaml.safe_load(fp.read())

    roles = myiam.list_roles(table=myiam_api.app.table)
    for role in roles:
        role_name = role["pk"].split("#")[-1]
        myiam.delete_role(table=myiam_api.app.table, role_name=role_name)

    for item in source_roles:
        logger.info("{role_name} => {policy_names}".format(**item))
        myiam.create_role(table=myiam_api.app.table, role_name=item["role_name"])
        myiam.update_role_attach_policies(
            table=myiam_api.app.table,
            role_name=item["role_name"],
            policy_names=item["policy_names"],
        )
