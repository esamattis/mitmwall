"""
mitmproxy addon runtime for mitmwall allowlist enforcement.
"""

from typing import Protocol

from .addon_logging import LOGGER, setup_logging
from .constants import RULES_DIR
from .rules import (
    MatchResult,
    Rule,
    describe_rule,
    load_rules,
    normalize_host,
    normalize_method,
    request_pathname,
)


class RequestLike(Protocol):
    """
    Subset of mitmproxy request attributes used by the addon.
    """

    pretty_host: str
    host: str
    method: str
    pretty_url: str


class FlowLike(Protocol):
    """
    Subset of mitmproxy flow behavior used by the addon.
    """

    request: RequestLike

    def kill(self) -> None:
        """
        Terminate the in-flight request flow immediately.
        """

        ...


class Mitmwall:
    """
    mitmproxy addon that enforces mitmwall hostname allow rules.
    """

    def __init__(self) -> None:
        """
        Initialize addon state without touching runtime configuration.
        """

        self.rules: list[Rule] = []
        self.rule_descriptions: tuple[str, ...] = ()

    def load(self, _loader: object) -> None:
        """
        Configure logging and load the current rules during addon startup.
        """

        setup_logging()
        LOGGER.info("addon loaded")
        self.reload_rules()

    def running(self) -> None:
        """
        Reload rules once mitmproxy has finished starting up.
        """

        self.reload_rules()

    def configure(self, _updated: set[str]) -> None:
        """
        Reload rules after mitmproxy configuration changes.
        """

        self.reload_rules()

    def reload_rules(self) -> None:
        """
        Load rules from disk and update logged descriptions when they change.
        """

        try:
            rules = load_rules()
        except Exception as exc:
            self.rules = []
            self.rule_descriptions = ()
            LOGGER.error(f"failed to load {RULES_DIR}: {exc}")
            return

        rule_descriptions = tuple(
            describe_rule(index, rule) for index, rule in enumerate(rules, start=1)
        )
        self.rules = rules

        if rule_descriptions == self.rule_descriptions:
            return

        self.rule_descriptions = rule_descriptions
        LOGGER.info(f"loaded {len(self.rules)} allow rule(s) from {RULES_DIR}")
        for description in self.rule_descriptions:
            LOGGER.info(description)

    def request(self, flow: FlowLike) -> None:
        """
        Allow matching requests and terminate flows that do not match any rule.
        """

        host = flow.request.pretty_host or flow.request.host
        method = flow.request.method
        url = flow.request.pretty_url
        pathname = request_pathname(url)
        LOGGER.debug(
            f"request method={method} host={host} pathname={pathname} url={url}"
        )

        result = self.is_allowed(host, method, pathname)
        if result.allowed:
            LOGGER.debug(f"allowed host={host} method={method} rule={result.rule_name}")
            return

        flow.kill()
        LOGGER.warning(
            f"blocked host={host} method={method} url={url}; no allow rule matched"
        )

    def is_allowed(
        self, host: str, method: str = "GET", pathname: str = "/"
    ) -> MatchResult:
        """
        Return whether any loaded rule allows the given request details.
        """

        normalized_host = normalize_host(host)
        normalized_method = normalize_method(method)
        for rule in self.rules:
            if rule.matches(normalized_host, normalized_method, pathname):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)


addons = [Mitmwall()]
