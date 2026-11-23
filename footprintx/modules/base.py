"""Standard interface every reconnaissance module implements (spec §5).

A module is one reconnaissance *capability* (e.g. subdomain discovery). It drives
one or more *integrations* (e.g. Subfinder, Amass), normalises their output into
:class:`~footprintx.core.models.Finding` objects and returns a ModuleResult.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from footprintx.core.config import ModuleConfig
from footprintx.core.models import ModuleResult, Target, TargetType

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext


class BaseModule(ABC):
    #: Unique id — used as the ``modules.<name>`` config key and in ``--exclude``.
    name: ClassVar[str]
    description: ClassVar[str]
    #: Seed target types that make this module relevant to a scan.
    applies_to: ClassVar[frozenset[TargetType]]
    #: Modules whose findings this one consumes. Unselected dependencies are ignored.
    depends_on: ClassVar[tuple[str, ...]] = ()
    #: Integration names (see ``footprintx.integrations``) this module can use.
    integrations: ClassVar[tuple[str, ...]] = ()
    #: Option names read from ``modules.<name>`` (besides ``enabled``); anything
    #: else in the config file is reported as an unknown setting.
    options: ClassVar[frozenset[str]] = frozenset()
    #: Used when the config file does not mention this module.
    enabled_by_default: ClassVar[bool] = True
    #: Sends traffic to the targets themselves (skipped in passive mode).
    active: ClassVar[bool] = False

    def __init__(self, config: ModuleConfig | None = None) -> None:
        self.config = config or ModuleConfig(enabled=self.enabled_by_default)

    def applies_to_target(self, target: Target) -> bool:
        return target.type in self.applies_to

    @abstractmethod
    async def run(self, context: ScanContext) -> ModuleResult:
        """Run against ``context`` (seed targets + findings of dependencies).

        Integrations that are missing should be skipped and reported in the result,
        not raised — the engine treats an exception as a module failure.
        """

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name!r}>"
