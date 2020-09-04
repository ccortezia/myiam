def create_primary_table(dynamodb, table_name):

    return dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "rule_action", "AttributeType": "S"},
            {"AttributeName": "rule_effect", "AttributeType": "S"},
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
        GlobalSecondaryIndexes=[
            {
                "IndexName": "sk_pk",
                "KeySchema": [
                    {"AttributeName": "sk", "KeyType": "HASH"},
                    {"AttributeName": "pk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
            },
            {
                "IndexName": "action_lookup",
                "KeySchema": [
                    {"AttributeName": "rule_action", "KeyType": "HASH"},
                    {"AttributeName": "rule_effect", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
            },
        ],
        StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
    )
