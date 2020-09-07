import pytest
from myiam.api import create_action, update_action, create_policy
from .ddbs_utils import get_new_events


# NOTE: These tests will be moved to whatever project hosts the stream lambdas.
pytestmark = pytest.mark.skip

def test_stream_1(ddbt, dynamodbstreams):

    create_action(ddbt, action_name="batch:SubmitJob")
    create_action(ddbt, action_name="batch:RegisterJobDefinition")
    update_action(ddbt, action_name="batch:SubmitJob", metavar=123)

    events, new_it = get_new_events(ddbt, dynamodbstreams)
    print(events)

    events, new_it = get_new_events(ddbt, dynamodbstreams, iterator=new_it)
    print(events)

    update_action(ddbt, action_name="batch:SubmitJob", metavar=444, newattr={'expression': 899})

    events, new_it = get_new_events(ddbt, dynamodbstreams, iterator=new_it)
    print(events)


def test_stream_2(ddbt, dynamodbstreams, generic_policy):

    create_policy(ddbt, policy_name="SalesDataReadOnly", **generic_policy)

    events, new_it = get_new_events(ddbt, dynamodbstreams)
    print(events)

    handle({"Records": events}, None)

    print(describe_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001"))
    print(describe_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001"))
