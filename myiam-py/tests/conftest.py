import pytest
import boto3
from myiam.dbsetup import create_primary_table

TEST_TABLE_NAME = "testmyiam"


@pytest.fixture(scope="session")
def dynamodb():
    return boto3.resource("dynamodb", region_name="localhost", endpoint_url="http://localhost:8000")


@pytest.fixture(scope="session")
def dynamodbstreams():
    return boto3.client(
        "dynamodbstreams", region_name="localhost", endpoint_url="http://localhost:8000"
    )


@pytest.fixture(scope="function")
def ddbt(request, dynamodb):
    table = dynamodb.Table(TEST_TABLE_NAME)
    try:
        table.delete()
    except table.meta.client.exceptions.ResourceNotFoundException:
        pass
    create_primary_table(dynamodb, TEST_TABLE_NAME)
    request.addfinalizer(table.delete)
    return table


@pytest.fixture
def generic_policy():
    return dict(
        schema_version="1.0",
        statements=[
            {
                "sid": "AllowReadData",
                "effect": "allow",
                "resources": "databases/sales",
                "actions": "QueryData",
            }
        ],
    )


@pytest.fixture
def multiaction_policy():
    return dict(
        schema_version="1.0",
        statements=[
            {
                "sid": "AllowCollaboration",
                "effect": "allow",
                "resources": "databases/sales",
                "actions": ["WriteData", "QueryData"],
            }
        ],
    )
