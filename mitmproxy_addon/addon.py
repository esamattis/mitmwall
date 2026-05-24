"""
mitmproxy addon runtime for mitmwall allowlist enforcement.
"""

from typing import Protocol

from .addon_config import AddonConfig
from .addon_logging import LOGGER, setup_logging
from .constants import DEFAULT_BLOCK_DNS, RULES_DIR
from .rules import (
    MatchResult,
    Rule,
    describe_rule,
    load_rules,
    normalize_host,
    normalize_method,
    request_pathname,
)

DNS_RESPONSE_CODE_REFUSED = 5


class HeadersLike(Protocol):
    """
    Minimal mutable header mapping exposed by mitmproxy requests.
    """

    def __setitem__(self, key: str, value: str, /) -> None:
        """
        Set or replace a header value.
        """

        ...

    def __getitem__(self, key: str, /) -> str:
        """
        Return a header value.
        """

        ...


class RequestLike(Protocol):
    """
    Subset of mitmproxy request attributes used by the addon.
    """

    pretty_host: str
    host: str
    method: str
    pretty_url: str
    headers: HeadersLike


class FlowLike(Protocol):
    """
    Subset of mitmproxy HTTP flow behavior used by the addon.
    """

    request: RequestLike

    def kill(self) -> None:
        """
        Terminate the in-flight request flow immediately.
        """

        ...


class DNSQuestionLike(Protocol):
    """
    Subset of mitmproxy DNS question attributes used by the addon.
    """

    name: str


class DNSRequestLike(Protocol):
    """
    Subset of mitmproxy DNS request behavior used by the addon.
    """

    question: DNSQuestionLike | None

    def fail(self, response_code: int) -> object:
        """
        Build a DNS error response for the request.
        """

        ...


class DNSFlowLike(Protocol):
    """
    Subset of mitmproxy DNS flow behavior used by the addon.
    """

    request: DNSRequestLike
    response: object | None


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
        self.block_dns: bool = DEFAULT_BLOCK_DNS

    def load(self, _loader: object) -> None:
        """
        Configure logging and load the current rules during addon startup.
        """

        addon_config = setup_logging()
        self.apply_addon_config(addon_config)
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

    def apply_addon_config(self, addon_config: AddonConfig) -> None:
        """
        Apply loaded runtime addon settings.
        """

        previous_block_dns = self.block_dns
        self.block_dns = addon_config.block_dns
        if self.block_dns != previous_block_dns:
            LOGGER.info(f"DNS filtering {'enabled' if self.block_dns else 'disabled'}")

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
            if result.inject_headers:
                for injected_header in result.inject_headers:
                    flow.request.headers[injected_header.name] = injected_header.value
                injected_header_names = ",".join(
                    header.name for header in result.inject_headers
                )
                LOGGER.debug(
                    f"allowed host={host} method={method} rule={result.rule_name} injected_headers={injected_header_names}"
                )
            else:
                LOGGER.debug(
                    f"allowed host={host} method={method} rule={result.rule_name}"
                )
            return

        flow.kill()
        LOGGER.warning(
            f"blocked host={host} method={method} url={url}; no allow rule matched"
        )

    def dns_request(self, flow: DNSFlowLike) -> None:
        """
        Forward DNS queries for allowed domains and refuse all other names.
        """

        if not self.block_dns:
            LOGGER.debug("allowed DNS request because block_dns is disabled")
            return

        question = flow.request.question
        if question is None:
            flow.response = flow.request.fail(DNS_RESPONSE_CODE_REFUSED)
            LOGGER.warning("blocked DNS request without a question")
            return

        host = question.name
        LOGGER.debug(f"dns request host={host}")
        result = self.is_dns_allowed(host)
        if result.allowed:
            LOGGER.debug(f"allowed DNS host={host} rule={result.rule_name}")
            return

        flow.response = flow.request.fail(DNS_RESPONSE_CODE_REFUSED)
        LOGGER.warning(f"blocked DNS host={host}; no allow rule matched")

    def is_dns_allowed(self, host: str) -> MatchResult:
        """
        Return whether any loaded rule allows DNS resolution for the hostname.
        """

        normalized_host = normalize_host(host)
        for rule in self.rules:
            if rule.matches_host(normalized_host):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)

    def is_allowed(
        self, host: str, method: str = "GET", pathname: str = "/"
    ) -> MatchResult:
        """
        Return whether any loaded rule allows the given request details.
        """

        normalized_host = normalize_host(host)
        normalized_method = normalize_method(method)
        first_match: Rule | None = None
        for rule in self.rules:
            if not rule.matches(normalized_host, normalized_method, pathname):
                continue

            if first_match is None:
                first_match = rule
            if rule.inject_headers:
                return MatchResult(
                    allowed=True,
                    rule_name=rule.name,
                    inject_headers=rule.inject_headers,
                )

        if first_match is not None:
            return MatchResult(
                allowed=True,
                rule_name=first_match.name,
                inject_headers=first_match.inject_headers,
            )
        return MatchResult(allowed=False)


addons = [Mitmwall()]
