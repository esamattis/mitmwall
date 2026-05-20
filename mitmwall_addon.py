"""mitmproxy addon for mitmwall allowlist enforcement.

Rules are loaded from /opt/mitmwall/rules.toml.

Supported allow rule formats:

    [[allow]]
    domain = "api.github.com"
    include_subdomains = false

    [[allow]]
    domain_regex = '(^|\\.)example\\.(com|org)$'
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

import tomllib

RULES_PATH = Path("/opt/mitmwall/rules.toml")
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

    def matches(self, host: str) -> bool:
        host = normalize_host(host)
        domain = normalize_host(self.domain)

        if host == domain:
            return True

        return self.include_subdomains and host.endswith(f".{domain}")


@dataclass(frozen=True)
class RegexRule:
    name: str
    pattern: re.Pattern[str]

    def matches(self, host: str) -> bool:
        return self.pattern.search(normalize_host(host)) is not None


Rule = DomainRule | RegexRule
ALLOW_RULE_KEYS = {"domain", "domain_regex", "include_subdomains"}


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


def load_rules(path: Path = RULES_PATH) -> list[Rule]:
    if not path.exists():
        raise FileNotFoundError(f"rules file does not exist: {path}")

    with path.open("rb") as file:
        config = tomllib.load(file)

    extra_top_level_keys = set(config) - {"allow"}
    if extra_top_level_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_top_level_keys))
        raise ValueError(f"rules.toml: unsupported top-level key(s): {keys}")

    allow_rules = config.get("allow", [])
    if not isinstance(allow_rules, list):
        raise ValueError("rules.toml: 'allow' must be a list of tables")

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

        if has_domain:
            validate_allowed_keys(typed_rule, {"domain", "include_subdomains"}, index)
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
                )
            )
        else:
            validate_allowed_keys(typed_rule, {"domain_regex"}, index)
            domain_regex = require_string(typed_rule, "domain_regex", index)
            try:
                pattern = re.compile(domain_regex, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"allow rule #{index}: invalid domain_regex {domain_regex!r}: {exc}"
                ) from exc
            parsed_rules.append(
                RegexRule(name=f"domain_regex {domain_regex!r}", pattern=pattern)
            )

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
            LOGGER.error(f"failed to load {RULES_PATH}: {exc}")
            return

        LOGGER.info(f"loaded {len(self.rules)} allow rule(s) from {RULES_PATH}")

    def request(self, flow: FlowLike) -> None:
        host = flow.request.pretty_host or flow.request.host
        method = flow.request.method
        url = flow.request.pretty_url
        LOGGER.debug(f"request method={method} host={host} url={url}")

        result = self.is_allowed(host)
        if result.allowed:
            LOGGER.debug(f"allowed host={host} rule={result.rule_name}")
            return

        flow.kill()
        LOGGER.warning(
            f"blocked host={host} method={method} url={url}; no allow rule matched"
        )

    def is_allowed(self, host: str) -> MatchResult:
        normalized_host = normalize_host(host)
        for rule in self.rules:
            if rule.matches(normalized_host):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)


addons = [Mitmwall()]
