"""
mitmproxy addon runtime for mitmwall allowlist enforcement.
"""

import socket
from collections.abc import Iterable, Sequence
from importlib import import_module
from typing import Callable, Protocol, TypeGuard, cast

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
    AllowTCPRule,
    DomainRule,
    MatchResult,
    describe_rule,
    describe_tcp_rule,
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


class DNSResourceRecordLike(Protocol):
    """
    Subset of mitmproxy DNS resource record attributes used by the addon.
    """

    ipv4_address: str | None
    ipv6_address: str | None


class DNSResponseLike(Protocol):
    """
    Subset of mitmproxy DNS response attributes used by the addon.
    """

    answers: list[DNSResourceRecordLike]


def is_dns_response_like(value: object) -> TypeGuard[DNSResponseLike]:
    """
    Return whether a value is a DNSResponseLike object.
    """

    return hasattr(value, "answers") and isinstance(
        getattr(value, "answers", None), list
    )


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
    response: object


class ServerConnLike(Protocol):
    """
    Subset of mitmproxy server connection attributes used by the addon.
    """

    address: tuple[str, int] | None


class ServerConnectionHookDataLike(Protocol):
    """
    Subset of mitmproxy server connection hook data used by the addon.
    """

    server: ServerConnLike


class TCPFlowLike(Protocol):
    """
    Subset of mitmproxy TCP flow behavior used by the addon.
    """

    server_conn: ServerConnLike


class Mitmwall:
    """
    mitmproxy addon that enforces mitmwall hostname allow rules.
    """

    def __init__(self) -> None:
        """
        Initialize addon state without touching runtime configuration.
        """

        self.rules: list[DomainRule] = []
        self.tcp_rules: list[AllowTCPRule] = []
        self.rule_descriptions: tuple[str, ...] = ()
        self.tcp_rule_descriptions: tuple[str, ...] = ()
        self.resolved_ips: dict[str, set[str]] = {}
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
            rules, tcp_rules = load_rules()
        except Exception as exc:
            self.rules = []
            self.tcp_rules = []
            self.rule_descriptions = ()
            self.tcp_rule_descriptions = ()
            LOGGER.error(f"failed to load {RULES_DIR}: {exc}")
            return

        rule_descriptions = tuple(
            describe_rule(index, rule) for index, rule in enumerate(rules, start=1)
        )
        tcp_rule_descriptions = tuple(
            describe_tcp_rule(index, rule)
            for index, rule in enumerate(tcp_rules, start=1)
        )
        self.rules = rules
        self.tcp_rules = tcp_rules

        if (
            rule_descriptions == self.rule_descriptions
            and tcp_rule_descriptions == self.tcp_rule_descriptions
        ):
            return

        self.rule_descriptions = rule_descriptions
        self.tcp_rule_descriptions = tcp_rule_descriptions
        LOGGER.info(f"loaded {len(self.rules)} allow rule(s) from {RULES_DIR}")
        for description in self.rule_descriptions:
            LOGGER.info(description)
        LOGGER.info(f"loaded {len(self.tcp_rules)} allow_tcp rule(s) from {RULES_DIR}")
        for description in self.tcp_rule_descriptions:
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

            if self.is_tcp_dns_allowed(host):
                LOGGER.debug(f"allowed DNS host={host} for allow_tcp rule")
                return

            flow.response = flow.request.fail(DNS_RESPONSE_CODE_REFUSED)
            LOGGER.warning(f"blocked DNS host={host}; no allow rule matched")
        finally:
            self.record_request_for_flow_history_clear()

    def dns_response(self, flow: DNSFlowLike) -> None:
        """
        Store resolved IP addresses from DNS responses for allow_tcp hostname tracking.
        """

        question = flow.request.question
        if question is None:
            return

        host = question.name
        if not self.is_tcp_dns_allowed(host):
            return

        response = flow.response
        if response is None:
            return

        if not is_dns_response_like(response):
            return

        normalized_host = normalize_host(host)
        resolved_ips: set[str] = set()
        for answer in response.answers:
            try:
                if answer.ipv4_address is not None:
                    resolved_ips.add(str(answer.ipv4_address))
            except ValueError:
                pass
            try:
                if answer.ipv6_address is not None:
                    resolved_ips.add(str(answer.ipv6_address))
            except ValueError:
                pass

        if resolved_ips:
            if normalized_host not in self.resolved_ips:
                self.resolved_ips[normalized_host] = set()
            self.resolved_ips[normalized_host].update(resolved_ips)
            LOGGER.debug(
                f"stored resolved IPs for {host}: {sorted(resolved_ips)}"
            )

    def server_connect(self, data: ServerConnectionHookDataLike) -> None:
        """
        Log server connection attempts before mitmproxy opens the upstream socket.
        """

        address = data.server.address
        if address is not None:
            host, port = address
            LOGGER.debug(f"server connection host={host} port={port}")

    def tcp_start(self, flow: TCPFlowLike) -> None:
        """
        Allow TCP connections that match allow_tcp rules and kill all others.
        """

        address = flow.server_conn.address
        if address is None:
            LOGGER.info("tcp connection with unknown destination")
            return

        host, port = address
        LOGGER.info(f"tcp connection host={host} port={port}")

        if self.is_allow_all_traffic():
            LOGGER.debug("allowed TCP connection because allow_all_traffic is enabled")
            return

        if self.is_tcp_allowed(host, port):
            LOGGER.debug(f"allowed TCP connection host={host} port={port}")
            return

        kill_method = getattr(flow, "kill", None)
        if callable(kill_method):
            _ = kill_method()
            LOGGER.warning(
                f"blocked TCP connection host={host} port={port}; no allow_tcp rule matched"
            )
        else:
            LOGGER.warning(
                f"would block TCP connection host={host} port={port} but flow.kill() not available"
            )

    def is_dns_allowed(self, host: str) -> MatchResult:
        """
        Return whether any loaded rule allows DNS resolution for the hostname.
        """

        normalized_host = normalize_host(host)
        for rule in self.rules:
            if rule.matches_host(normalized_host):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)

    def is_tcp_dns_allowed(self, host: str) -> bool:
        """
        Return whether any allow_tcp rule has a hostname matching the DNS query.
        """

        normalized_host = normalize_host(host)
        for rule in self.tcp_rules:
            if not rule.is_ip_address():
                if normalize_host(rule.host) == normalized_host:
                    return True
        return False

    def is_tcp_allowed(self, host: str, port: int) -> bool:
        """
        Return whether any allow_tcp rule allows the TCP connection.
        """

        for rule in self.tcp_rules:
            if rule.port != port:
                continue
            if rule.is_ip_address():
                if rule.host == host:
                    return True
            else:
                normalized_rule_host = normalize_host(rule.host)
                if normalize_host(host) == normalized_rule_host:
                    return True
                resolved_ips = self.resolved_ips.get(normalized_rule_host, set())
                if host in resolved_ips:
                    return True
        return False

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
