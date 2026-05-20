"""mitmproxy addon for mitmwall allowlist enforcement.

Rules are loaded from TOML files in /opt/mitmwall/rules.d.

Supported allow rule formats:

    [[allow]]
    domain = "api.github.com"
    include_subdomains = false
    methods = ["GET"]

    [[allow]]
    domain_regex = '(^|\\.)example\\.(com|org)$'
    methods = "ANY"
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

import tomllib

RULES_DIR = Path("/opt/mitmwall/rules.d")
LOGGER = logging.getLogger("mitmwall")
LOGGER.setLevel(logging.DEBUG)
LOGGER.propagate = False


def setup_logging() -> None:
    """Send addon logs to stderr so systemd journal captures them."""
    if LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOGGER.addHandler(handler)


@dataclass(frozen=True)
class MatchResult:
    allowed: bool
    rule_name: str | None = None


@dataclass(frozen=True)
class DomainRule:
    name: str
    domain: str
    include_subdomains: bool
    methods: tuple[str, ...]

    def matches(self, host: str, method: str) -> bool:
        if not method_matches(self.methods, method):
            return False

        host = normalize_host(host)
        domain = normalize_host(self.domain)

        if host == domain:
            return True

        return self.include_subdomains and host.endswith(f".{domain}")


@dataclass(frozen=True)
class RegexRule:
    name: str
    pattern: re.Pattern[str]
    methods: tuple[str, ...]

    def matches(self, host: str, method: str) -> bool:
        if not method_matches(self.methods, method):
            return False

        return self.pattern.search(normalize_host(host)) is not None


Rule = DomainRule | RegexRule
DEFAULT_ALLOWED_METHODS = ("GET", "HEAD")
ANY_METHOD = "ANY"
ALLOW_RULE_KEYS = {"domain", "domain_regex", "include_subdomains", "methods"}


class RequestLike(Protocol):
    pretty_host: str
    host: str
    method: str
    pretty_url: str


class FlowLike(Protocol):
    request: RequestLike

    def kill(self) -> None: ...


def normalize_host(host: str) -> str:
    """Normalize hostnames before rule matching."""
    return host.strip().rstrip(".").lower()


def normalize_method(method: str) -> str:
    """Normalize HTTP methods before rule matching."""
    return method.strip().upper()


def method_matches(allowed_methods: tuple[str, ...], method: str) -> bool:
    normalized_method = normalize_method(method)
    return ANY_METHOD in allowed_methods or normalized_method in allowed_methods


def require_string(rule: dict[str, Any], key: str, index: int) -> str:
    value = rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"allow rule #{index}: {key!r} must be a non-empty string")
    return value


def validate_allowed_keys(
    rule: dict[str, Any], allowed_keys: set[str], index: int
) -> None:
    extra_keys = set(rule) - allowed_keys
    if extra_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_keys))
        raise ValueError(f"allow rule #{index}: unsupported key(s): {keys}")


def parse_methods(rule: dict[str, Any], index: int) -> tuple[str, ...]:
    if "methods" not in rule:
        return DEFAULT_ALLOWED_METHODS

    value = rule["methods"]
    if isinstance(value, str):
        method = normalize_method(value)
        if method == ANY_METHOD:
            return (ANY_METHOD,)
        raise ValueError(
            f"allow rule #{index}: string 'methods' value must be 'ANY'"
        )

    if not isinstance(value, list) or not value:
        raise ValueError(
            f"allow rule #{index}: 'methods' must be 'ANY' or a non-empty list"
        )

    methods: list[str] = []
    for method_index, method in enumerate(value, start=1):
        if not isinstance(method, str) or not method.strip():
            raise ValueError(
                f"allow rule #{index}: methods item #{method_index} must be a non-empty string"
            )
        normalized_method = normalize_method(method)
        if normalized_method == ANY_METHOD:
            raise ValueError(
                f"allow rule #{index}: use methods = 'ANY' instead of including 'ANY' in a list"
            )
        methods.append(normalized_method)

    return tuple(dict.fromkeys(methods))


def parse_rules_file(path: Path) -> list[Rule]:
    with path.open("rb") as file:
        config = tomllib.load(file)

    extra_top_level_keys = set(config) - {"allow"}
    if extra_top_level_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_top_level_keys))
        raise ValueError(f"unsupported top-level key(s): {keys}")

    allow_rules = config.get("allow", [])
    if not isinstance(allow_rules, list):
        raise ValueError("'allow' must be a list of tables")

    parsed_rules: list[Rule] = []
    for index, rule in enumerate(allow_rules, start=1):
        if not isinstance(rule, dict):
            raise ValueError(f"allow rule #{index}: rule must be a table")

        typed_rule = cast(dict[str, Any], rule)
        validate_allowed_keys(typed_rule, ALLOW_RULE_KEYS, index)

        has_domain = "domain" in typed_rule
        has_domain_regex = "domain_regex" in typed_rule
        if has_domain and has_domain_regex:
            raise ValueError(
                f"allow rule #{index}: cannot set both 'domain' and 'domain_regex'"
            )
        if not has_domain and not has_domain_regex:
            raise ValueError(
                f"allow rule #{index}: exactly one of 'domain' or 'domain_regex' is required"
            )

        methods = parse_methods(typed_rule, index)

        if has_domain:
            validate_allowed_keys(
                typed_rule, {"domain", "include_subdomains", "methods"}, index
            )
            domain = require_string(typed_rule, "domain", index)
            include_subdomains = typed_rule.get("include_subdomains", False)
            if not isinstance(include_subdomains, bool):
                raise ValueError(
                    f"allow rule #{index}: 'include_subdomains' must be a boolean"
                )
            normalized_domain = normalize_host(domain)
            parsed_rules.append(
                DomainRule(
                    name=f"domain {normalized_domain}",
                    domain=normalized_domain,
                    include_subdomains=include_subdomains,
                    methods=methods,
                )
            )
        else:
            validate_allowed_keys(typed_rule, {"domain_regex", "methods"}, index)
            domain_regex = require_string(typed_rule, "domain_regex", index)
            try:
                pattern = re.compile(domain_regex, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"allow rule #{index}: invalid domain_regex {domain_regex!r}: {exc}"
                ) from exc
            parsed_rules.append(
                RegexRule(
                    name=f"domain_regex {domain_regex!r}",
                    pattern=pattern,
                    methods=methods,
                )
            )

    return parsed_rules


def load_rules(path: Path = RULES_DIR) -> list[Rule]:
    if not path.exists():
        raise FileNotFoundError(f"rules directory does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"rules path is not a directory: {path}")

    parsed_rules: list[Rule] = []
    rule_files = sorted(
        child for child in path.iterdir() if child.is_file() and child.suffix == ".toml"
    )
    for rule_file in rule_files:
        try:
            parsed_rules.extend(parse_rules_file(rule_file))
        except Exception as exc:
            raise ValueError(f"failed to load {rule_file}: {exc}") from exc

    return parsed_rules


class Mitmwall:
    def __init__(self) -> None:
        self.rules: list[Rule] = []
        setup_logging()

    def load(self, loader) -> None:  # noqa: ANN001 - mitmproxy controls this signature.
        LOGGER.info("addon loaded")
        self.reload_rules()

    def running(self) -> None:
        self.reload_rules()

    def configure(self, updated) -> None:  # noqa: ANN001 - mitmproxy controls this signature.
        # Reload on mitmproxy config changes. This gives operators a lightweight
        # way to pick up edits with `:set`/reload-like workflows without restart.
        self.reload_rules()

    def reload_rules(self) -> None:
        try:
            self.rules = load_rules()
        except Exception as exc:
            # Fail closed: if the allowlist is missing or invalid, block all traffic.
            self.rules = []
            LOGGER.error(f"failed to load {RULES_DIR}: {exc}")
            return

        LOGGER.info(f"loaded {len(self.rules)} allow rule(s) from {RULES_DIR}")

    def request(self, flow: FlowLike) -> None:
        host = flow.request.pretty_host or flow.request.host
        method = flow.request.method
        url = flow.request.pretty_url
        LOGGER.debug(f"request method={method} host={host} url={url}")

        result = self.is_allowed(host, method)
        if result.allowed:
            LOGGER.debug(f"allowed host={host} method={method} rule={result.rule_name}")
            return

        flow.kill()
        LOGGER.warning(
            f"blocked host={host} method={method} url={url}; no allow rule matched"
        )

    def is_allowed(self, host: str, method: str = "GET") -> MatchResult:
        normalized_host = normalize_host(host)
        normalized_method = normalize_method(method)
        for rule in self.rules:
            if rule.matches(normalized_host, normalized_method):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)


addons = [Mitmwall()]
