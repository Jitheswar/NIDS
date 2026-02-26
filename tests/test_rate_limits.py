import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

from main import app
from middleware.rate_limit import (
    audit_query_rate_limit,
    auth_general_rate_limit,
    security_mutation_rate_limit,
    security_read_rate_limit,
    sensor_activate_rate_limit,
)


def _get_route(path: str, method: str):
    for route in app.routes:
        if getattr(route, "path", None) == path and method in getattr(route, "methods", set()):
            return route
    raise AssertionError(f"Route not found: {method} {path}")


def _route_dependencies(route):
    return {dependency.call for dependency in route.dependant.dependencies}


def test_sensor_routes_have_limits():
    list_route = _get_route("/sensors/", "GET")
    activate_route = _get_route("/sensors/activate", "POST")

    assert auth_general_rate_limit in _route_dependencies(list_route)
    assert sensor_activate_rate_limit in _route_dependencies(activate_route)


def test_audit_routes_have_limits():
    logs_route = _get_route("/audit/logs", "GET")
    assert audit_query_rate_limit in _route_dependencies(logs_route)


def test_security_routes_have_limits():
    anomalies_route = _get_route("/security/anomalies", "GET")
    run_route = _get_route("/security/rotation-health/run", "POST")

    assert security_read_rate_limit in _route_dependencies(anomalies_route)
    assert security_mutation_rate_limit in _route_dependencies(run_route)
