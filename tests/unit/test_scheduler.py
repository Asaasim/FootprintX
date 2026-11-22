import pytest

from footprintx.core.models import ALL_TARGET_TYPES
from footprintx.core.scheduler import DependencyCycleError, build_execution_plan
from footprintx.modules import MODULE_REGISTRY
from footprintx.modules.base import BaseModule


def names(plan):
    return [[m.name for m in layer] for layer in plan]


def test_full_plan_respects_dependencies():
    modules = [cls() for cls in MODULE_REGISTRY.values()]
    plan = build_execution_plan(modules)
    stage = {m.name: i for i, layer in enumerate(plan) for m in layer}
    assert set(stage) == set(MODULE_REGISTRY)
    for m in modules:
        for dep in m.depends_on:
            assert stage[dep] < stage[m.name], f"{m.name} runs before its dependency {dep}"


def test_unselected_dependencies_are_ignored():
    modules = [MODULE_REGISTRY["technology_detection"](), MODULE_REGISTRY["http_probe"]()]
    assert names(build_execution_plan(modules)) == [["http_probe"], ["technology_detection"]]


def test_cycle_is_detected():
    class A(BaseModule):
        name, description, applies_to, depends_on = "a", "", ALL_TARGET_TYPES, ("b",)

        async def run(self, context):
            raise NotImplementedError

    class B(A):
        name, depends_on = "b", ("a",)

    with pytest.raises(DependencyCycleError):
        build_execution_plan([A(), B()])
