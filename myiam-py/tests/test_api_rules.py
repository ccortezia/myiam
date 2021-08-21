import pytest
from myiam import (
    create_rule,
    describe_rule,
    delete_rule,
    delete_rules_by_sid,
    convert_policy_statement_into_rules,
)


def test_create_rule(ddbt):
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "-", "001", "db:FetchRows", "allow")


def test_describe_rule(ddbt):
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "-", "001", "db:FetchRows", "allow")
    rule = describe_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001")
    print(rule)


def test_delete_rule(ddbt):
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "-", "001", "db:FetchRows", "allow")
    delete_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001")
    rule = describe_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001")
    print(rule)


def test_delete_rules_by_sid(ddbt):
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "-", "001", "db:FetchRows", "allow")
    create_rule(ddbt, "PolicyA", "ReadOnlyAccess", "-", "002", "db:FetchRows", "deny")
    create_rule(ddbt, "PolicyB", "ReadOnlyAccess", "-", "001", "db:FetchRows", "deny")
    delete_rules_by_sid(ddbt, "PolicyA", "ReadOnlyAccess")
    rule = describe_rule(ddbt, "PolicyA", "ReadOnlyAccess", "001")
    print(rule)
    rule = describe_rule(ddbt, "PolicyA", "ReadOnlyAccess", "002")
    print(rule)
    rule = describe_rule(ddbt, "PolicyB", "ReadOnlyAccess", "001")
    print(rule)


@pytest.mark.parametrize(
    "statement,rules",
    [
        (
            {
                "pk": "policy#PolicyA",
                "sk": "sid#AllowReadData",
                "effect": "allow",
                "resources": ["databases/1"],
                "actions": ["db:ReadData"],
                "statement_signatures": {"db:ReadData": "md5:000"},
            },
            [
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowReadData",
                    "rule_id": "0",
                    "action_name": "db:ReadData",
                    "effect": "allow",
                    "resource_spec": "databases/1",
                    "condition": None,
                    "statement_signature": "md5:000",
                }
            ],
        ),
        (
            {
                "pk": "policy#PolicyA",
                "sk": "sid#AllowReadData",
                "effect": "allow",
                "resources": ["databases/1", "caches/*"],
                "actions": ["db:ReadData"],
                "statement_signatures": {"db:ReadData": "md5:000"},
            },
            [
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowReadData",
                    "rule_id": "0",
                    "action_name": "db:ReadData",
                    "effect": "allow",
                    "resource_spec": "databases/1",
                    "condition": None,
                    "statement_signature": "md5:000",
                },
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowReadData",
                    "rule_id": "1",
                    "action_name": "db:ReadData",
                    "effect": "allow",
                    "resource_spec": "caches/*",
                    "condition": None,
                    "statement_signature": "md5:000",
                },
            ],
        ),
        (
            {
                "pk": "policy#PolicyA",
                "sk": "sid#AllowAccessData",
                "effect": "allow",
                "resources": ["databases/1", "caches/*"],
                "actions": ["db:ReadData", "db:WriteData"],
                "statement_signatures": {"db:WriteData": "md5:abc", "db:ReadData": "md5:000"},
            },
            [
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowAccessData",
                    "rule_id": "0",
                    "action_name": "db:ReadData",
                    "effect": "allow",
                    "resource_spec": "databases/1",
                    "condition": None,
                    "statement_signature": "md5:000",
                },
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowAccessData",
                    "rule_id": "1",
                    "action_name": "db:ReadData",
                    "effect": "allow",
                    "resource_spec": "caches/*",
                    "condition": None,
                    "statement_signature": "md5:000",
                },
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowAccessData",
                    "rule_id": "2",
                    "action_name": "db:WriteData",
                    "effect": "allow",
                    "resource_spec": "databases/1",
                    "condition": None,
                    "statement_signature": "md5:abc",
                },
                {
                    "policy_name": "PolicyA",
                    "statement_id": "AllowAccessData",
                    "rule_id": "3",
                    "action_name": "db:WriteData",
                    "effect": "allow",
                    "resource_spec": "caches/*",
                    "condition": None,
                    "statement_signature": "md5:abc",
                },
            ],
        ),
    ],
)
def test_convert_policy_statement_into_rules(statement, rules):
    assert convert_policy_statement_into_rules(statement) == rules
