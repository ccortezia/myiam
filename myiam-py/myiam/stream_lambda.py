import boto3
from myiam import create_rule, delete_rules_by_sid, convert_policy_statement_into_rules


dynamodb = boto3.resource("dynamodb", region_name="localhost", endpoint_url="http://localhost:8000")

ddbt = dynamodb.Table("testmyiam")


def handle_stream_event(event, context):

    records = event["Records"]

    for record in records:

        pk = record["dynamodb"]['Keys'].get("pk").get("S", "")
        sk = record["dynamodb"]['Keys'].get("sk").get("S", "")

        is_policy_pk = pk.startswith("policy#")
        is_statement_sk = sk.startswith("sid#")

        if record["eventName"] == "INSERT" and is_policy_pk and is_statement_sk:

            # Convert statement into rules
            rules = convert_policy_statement_into_rules({
                'pk': record["dynamodb"]["NewImage"]["pk"]["S"],
                'sk': record["dynamodb"]["NewImage"]["sk"]["S"],
                'effect': record["dynamodb"]["NewImage"]["effect"]["S"],
                'resources': [record["dynamodb"]["NewImage"]["resources"]["S"]],
                'actions': [record["dynamodb"]["NewImage"]["actions"]["S"]],
            })

            # Remove existing rules for statement.
            policy_name = pk.split("#")[-1]
            statement_id = sk.split("#")[-1]
            delete_rules_by_sid(ddbt, policy_name, statement_id)

            # Insert new rules for statement
            for rule_id, rule in enumerate(rules):
                create_rule(ddbt, **rule)
