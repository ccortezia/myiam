from myiam import (
    list_resolvers,
    create_resolver,
    describe_resolver,
    delete_resolver,
)


def test_create_resolver(ddbt):
    create_resolver(ddbt, request_key="org.io:GET:/api", action="batch:SubmitJob", resource="job")
    resolvers = list_resolvers(ddbt)
    print(resolvers)


def test_describe_resolver(ddbt):
    create_resolver(ddbt, request_key="org.io:GET:/api", action="batch:SubmitJob", resource="job")
    resolver = describe_resolver(ddbt, request_key="org.io:GET:/api")
    print(resolver)


def test_delete_resolver(ddbt):
    create_resolver(ddbt, request_key="org.io:GET:/api", action="batch:SubmitJob", resource="job")
    delete_resolver(ddbt, request_key="org.io:GET:/api")
    resolver = describe_resolver(ddbt, request_key="org.io:GET:/api")
    print(resolver)
