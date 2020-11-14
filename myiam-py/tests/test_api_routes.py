from myiam import (
    list_routes,
    create_route_domain,
    describe_route_domain,
    create_route,
    delete_route,
)


def test_list_routes(ddbt):
    create_route_domain(ddbt, "myiam", description="MyIAM API action routes")
    create_route(ddbt, "myiam", "GET:/myiam/ListUsers", "myiam:ListUsers")
    results = list_routes(ddbt)
    print(results)


def test_create_route_domain(ddbt):
    create_route_domain(ddbt, "myiam", description="MyIAM API action routes")
    results = list_routes(ddbt)
    print(results)


def test_create_route(ddbt):
    create_route_domain(ddbt, "myiam", description="MyIAM API action routes")
    create_route(ddbt, "myiam", "GET:/myiam/ListUsers", "myiam:ListUsers")
    results = list_routes(ddbt)
    print(results)


def test_describe_route_domain(ddbt):
    create_route_domain(ddbt, "myiam", description="MyIAM API action routes")
    create_route(ddbt, "myiam", "GET:/myiam/ListUsers", "myiam:ListUsers")
    results = describe_route_domain(ddbt, "myiam")
    print(results)


def test_delete_route(ddbt):
    create_route_domain(ddbt, "myiam", description="MyIAM API action routes")
    create_route(ddbt, "myiam", "GET:/myiam/ListUsers", "myiam:ListUsers")
    results = list_routes(ddbt)
    print(results)
    results = delete_route(ddbt, "myiam", "GET:/myiam/ListUsers")
    results = list_routes(ddbt)
    print(results)
