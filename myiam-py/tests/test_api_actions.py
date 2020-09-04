from myiam import (
    list_actions,
    create_action,
    describe_action,
    update_action,
    delete_action,
)


def test_create_action(ddbt):
    create_action(ddbt, action_name="batch:SubmitJob")
    actions = list_actions(ddbt,)
    print(actions)


def test_describe_action(ddbt):
    create_action(ddbt, action_name="batch:SubmitJob")
    action = describe_action(ddbt, action_name="batch:SubmitJob")
    print(action)


def test_update_action(ddbt):
    create_action(ddbt, action_name="batch:SubmitJob")
    update_action(ddbt, action_name="batch:SubmitJob")
    action = describe_action(ddbt, action_name="batch:SubmitJob")
    print(action)


def test_delete_action(ddbt):
    create_action(ddbt, action_name="batch:SubmitJob")
    delete_action(ddbt, action_name="batch:SubmitJob")
    action = describe_action(ddbt, action_name="batch:SubmitJob")
    print(action)
