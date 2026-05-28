"""
mitmproxy addon runtime for mitmwall allowlist enforcement.
"""

import socket
from collections.abc import Iterable, Sequence
from importlib import import_module
from typing import Callable, Protocol, cast

from .addon_config import AddonConfig
from .addon_logging import LOGGER, setup_logging
from .constants import (
    DEFAULT_BLOCK_DNS,
    DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL,
    DEFAULT_FLOW_HISTORY_KEEP_ENTRIES,
    OPTION_ALLOW_ALL_TRAFFIC,
    RULES_DIR,
)
from .rules import (
    DomainRule,
    MatchResult,
    describe_rule,
    load_rules,
    normalize_host,
    normalize_method,
    request_pathname,
)

DNS_RESPONSE_CODE_REFUSED = 5


class LoaderLike(Protocol):
    """
    Subset of mitmproxy's loader used to register addon options.
    """

    def add_option(
        self,
        name: str,
        typespec: type[object],
        default: object,
        help: str,
    ) -> None:
        """
        Register a mitmproxy option.
        """

        ...


class CtxOptionsLike(Protocol):
    """
    Subset of mitmproxy.ctx.options used by the addon.
    """

    ...


class MitmproxyCommandCallerLike(Protocol):
    """
    Subset of mitmproxy's command manager used by the addon.
    """

    def call(self, command_name: str, *args: object) -> object:
        """
        Execute a mitmproxy command by name.
        """

        ...


class MitmproxyMasterLike(Protocol):
    """
    Subset of mitmproxy's master object used by the addon.
    """

    commands: MitmproxyCommandCallerLike
    addons: "MitmproxyAddonManagerLike"


class MitmproxyAddonManagerLike(Protocol):
    """
    Subset of mitmproxy's addon manager used by the addon.
    """

    def get(self, addon_name: str) -> object | None:
        """
        Return a loaded mitmproxy addon by name.
        """

        ...


class MitmproxyContextLike(Protocol):
    """
    Subset of mitmproxy.ctx used by the addon.
    """

    master: MitmproxyMasterLike
    options: CtxOptionsLike


class MitmproxyViewLike(Protocol):
    """
    Subset of mitmproxy's view addon used to trim flow history.
    """

    def clear(self) -> None:
        """
        Clear all stored flows from the view.
        """

        ...

    def add(self, flows: Sequence[object]) -> None:
        """
        Add flows back to the view.
        """

        ...


def get_mitmproxy_view_store_values(view: object) -> list[object]:
    """
    Return mitmproxy view store values after validating the private store shape.
    """

    store: object | None = getattr(view, "_store", None)
    if store is None:
        raise RuntimeError("mitmproxy view addon does not expose _store")

    values_method = getattr(store, "values", None)
    if not callable(values_method):
        raise RuntimeError("mitmproxy view _store does not expose values()")

    return list(cast(Iterable[object], values_method()))


def call_mitmproxy_full_flow_history_clear(ctx: MitmproxyContextLike) -> None:
    """
    Clear all mitmproxy flow history using the stable command interface.
    """

    _result = ctx.master.commands.call("view.clear")


def trim_mitmproxy_view_flow_history(view: MitmproxyViewLike, keep_entries: int) -> int:
    """
    Trim mitmproxy's view to the newest stored flows and return the retained count.
    """

    recent_flows = get_mitmproxy_view_store_values(view)[-keep_entries:]
    view.clear()
    view.add(recent_flows)
    return len(recent_flows)


def clear_mitmproxy_flow_history(keep_entries: int) -> int:
    """
    Trim mitmproxy's flow history, falling back to a full clear if trimming fails.
    """

    ctx = cast(MitmproxyContextLike, cast(object, import_module("mitmproxy.ctx")))
    try:
        view = ctx.master.addons.get("view")
        if view is None:
            raise RuntimeError("mitmproxy view addon is not loaded")

        return trim_mitmproxy_view_flow_history(
            cast(MitmproxyViewLike, view),
            keep_entries,
        )
    except Exception as exc:
        LOGGER.error(f"failed to trim mitmproxy flow history: {exc}; clearing all")
        call_mitmproxy_full_flow_history_clear(ctx)
        return 0


def get_allow_all_traffic_option() -> bool:
    """
    Return whether the allow_all_traffic mitmproxy option is enabled.
    """

    ctx = cast(MitmproxyContextLike, cast(object, import_module("mitmproxy.ctx")))
    return cast(bool, getattr(ctx.options, OPTION_ALLOW_ALL_TRAFFIC))


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

        self.rules: list[DomainRule] = []
        self.rule_descriptions: tuple[str, ...] = ()
        self.block_dns: bool = DEFAULT_BLOCK_DNS
        self.flow_history_clear_interval: int = DEFAULT_FLOW_HISTORY_CLEAR_INTERVAL
        self.flow_history_keep_entries: int = DEFAULT_FLOW_HISTORY_KEEP_ENTRIES
        self.requests_since_flow_history_clear: int = 0
        self.flow_history_clearer: Callable[[int], int] = clear_mitmproxy_flow_history
        self.is_allow_all_traffic: Callable[[], bool] = lambda: False
        self.local_hostname: str = normalize_host(socket.gethostname())

    def load(self, loader: LoaderLike) -> None:
        """
        Configure logging, register options, and load rules during addon startup.
        """

        addon_config = setup_logging()
        self.apply_addon_config(addon_config)
        loader.add_option(
            name=OPTION_ALLOW_ALL_TRAFFIC,
            typespec=bool,
            default=False,
            help="mitmwall: Temporarily allow all traffic regardless of allow rules",
        )
        self.is_allow_all_traffic = get_allow_all_traffic_option
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
        previous_flow_history_clear_interval = self.flow_history_clear_interval
        previous_flow_history_keep_entries = self.flow_history_keep_entries
        self.block_dns = addon_config.block_dns
        self.flow_history_clear_interval = addon_config.flow_history_clear_interval
        self.flow_history_keep_entries = addon_config.flow_history_keep_entries
        if self.block_dns != previous_block_dns:
            LOGGER.info(f"DNS filtering {'enabled' if self.block_dns else 'disabled'}")
        if (
            self.flow_history_clear_interval != previous_flow_history_clear_interval
            or self.flow_history_keep_entries != previous_flow_history_keep_entries
        ):
            self.requests_since_flow_history_clear = 0
            LOGGER.info(
                "flow history will be trimmed every "
                + f"{self.flow_history_clear_interval} request(s), keeping "
                + f"{self.flow_history_keep_entries} entries"
            )

    def record_request_for_flow_history_clear(self) -> None:
        """
        Count a proxied request and clear mitmproxy flow history at the interval.
        """

        self.requests_since_flow_history_clear += 1
        if self.requests_since_flow_history_clear < self.flow_history_clear_interval:
            return

        self.requests_since_flow_history_clear = 0
        try:
            retained_entries = self.flow_history_clearer(self.flow_history_keep_entries)
        except Exception as exc:
            LOGGER.error(f"failed to clear mitmproxy flow history: {exc}")
            return

        LOGGER.info(f"trimmed mitmproxy flow history to {retained_entries} entries")

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

        if self.is_allow_all_traffic():
            LOGGER.debug("allowed request because allow_all_traffic is enabled")
            self.record_request_for_flow_history_clear()
            return

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
        else:
            flow.kill()
            LOGGER.warning(
                f"blocked host={host} method={method} url={url}; no allow rule matched"
            )

        self.record_request_for_flow_history_clear()

    def dns_request(self, flow: DNSFlowLike) -> None:
        """
        Forward DNS queries for allowed domains and refuse all other names.
        """

        try:
            if self.is_allow_all_traffic():
                LOGGER.debug("allowed DNS request because allow_all_traffic is enabled")
                return
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

            if self.is_local_hostname(host):
                LOGGER.debug(
                    f"allowed DNS host={host} because it is the local hostname"
                )
                return

            flow.response = flow.request.fail(DNS_RESPONSE_CODE_REFUSED)
            LOGGER.warning(f"blocked DNS host={host}; no allow rule matched")
        finally:
            self.record_request_for_flow_history_clear()

    def is_dns_allowed(self, host: str) -> MatchResult:
        """
        Return whether any loaded rule allows DNS resolution for the hostname.
        """

        normalized_host = normalize_host(host)
        for rule in self.rules:
            if rule.matches_host(normalized_host):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)

    def is_local_hostname(self, host: str) -> bool:
        """
        Return whether a DNS query is for the current machine hostname.
        """

        return bool(self.local_hostname) and normalize_host(host) == self.local_hostname

    def is_allowed(
        self, host: str, method: str = "GET", pathname: str = "/"
    ) -> MatchResult:
        """
        Return whether any loaded rule allows the given request details.
        """

        normalized_host = normalize_host(host)
        normalized_method = normalize_method(method)
        first_match: DomainRule | None = None
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
