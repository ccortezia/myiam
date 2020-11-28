# MyIAM

MyIAM offers application-agnostic policy-based access-control utilities.

Projects can leverage utilities independently from different composition levels:
* `myiam-spec`: data models and protocols for access-control administration and enforcement.
* [`myiam-py`](./myiam-py/README.md): data client implementation written in Python.
* [`myiam-cdk`](./myiam-cdk/README.md): AWS infrastructure components.
* [`myiam-api`](./myiam-api/README.md): access-control administration HTTP API built on top of `myiam-py`.
* `myiam-ui`: graphical user interface built on top of `myiam-api`.
* `myiam-aws`: reference deployment of aforementioned components.


Follow the [TODO](./TODO.md) list.
