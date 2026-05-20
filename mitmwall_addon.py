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

    [[allow]]
    domain = "github.com"
    pathname_pattern = "/esamattis/:repo.git/git-upload-pack"
"""

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeGuard
from urllib.parse import urlsplit

import tomllib

RULES_DIR = Path("/opt/mitmwall/rules.d")
PLUGIN_CONFIG_FILE = Path("/opt/mitmwall/plugin_config.toml")
DEFAULT_LOG_LEVEL_NAME = "info"
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
LOGGER = logging.getLogger("mitmwall")
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False


@dataclass(frozen=True)
class PluginConfig:
    """Runtime plugin settings loaded from plugin_config.toml."""

    log_level_name: str
    log_level: int


def default_plugin_config() -> PluginConfig:
    """Return the built-in plugin configuration defaults."""
    return PluginConfig(
        log_level_name=DEFAULT_LOG_LEVEL_NAME,
        log_level=LOG_LEVELS[DEFAULT_LOG_LEVEL_NAME],
    )


def parse_log_level(value: object) -> tuple[str, int]:
    """Parse and validate a plugin log level value."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("'log_level' must be a non-empty string")

    normalized = value.strip().lower()
    if normalized not in LOG_LEVELS:
        allowed = ", ".join(sorted(LOG_LEVELS))
        raise ValueError(f"'log_level' must be one of: {allowed}")

    return normalized, LOG_LEVELS[normalized]


def parse_plugin_config(config_value: object) -> PluginConfig:
    """Parse and validate plugin_config.toml contents."""
    if not is_toml_table(config_value):
        raise ValueError("top-level TOML value must be a table")

    extra_top_level_keys = set(config_value) - {"log_level"}
    if extra_top_level_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_top_level_keys))
        raise ValueError(f"unsupported top-level key(s): {keys}")

    log_level_name, log_level = parse_log_level(
        config_value.get("log_level", DEFAULT_LOG_LEVEL_NAME)
    )
    return PluginConfig(log_level_name=log_level_name, log_level=log_level)


def load_plugin_config(path: Path = PLUGIN_CONFIG_FILE) -> PluginConfig:
    """Load plugin runtime configuration from a TOML file."""
    if not path.exists():
        return default_plugin_config()

    with path.open("rb") as file:
        config_value = tomllib.load(file)

    return parse_plugin_config(config_value)


def apply_log_level(log_level: int) -> None:
    """Apply the selected log level to the addon logger and its handlers."""
    LOGGER.setLevel(log_level)
    for handler in LOGGER.handlers:
        handler.setLevel(log_level)


def setup_logging() -> None:
    """Send addon logs to stderr so systemd journal captures them."""
    if not LOGGER.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        LOGGER.addHandler(handler)

    try:
        plugin_config = load_plugin_config()
    except Exception as exc:
        default_config = default_plugin_config()
        apply_log_level(default_config.log_level)
        message = (
            f"failed to load {PLUGIN_CONFIG_FILE}: {exc}; "
            + f"using log_level={default_config.log_level_name}"
        )
        LOGGER.error(message)
        return

    apply_log_level(plugin_config.log_level)


@dataclass(frozen=True)
class MatchResult:
    """Result of evaluating a request against the allow rules."""

    allowed: bool
    rule_name: str | None = None


@dataclass(frozen=True)
class PathnameFilter:
    """Compiled pathname matcher attached to an allow rule."""

    name: str
    pattern: re.Pattern[str]
    uses_search: bool
    kind: str
    source: str

    def matches(self, pathname: str) -> bool:
        """Return whether the pathname satisfies this filter."""
        if self.uses_search:
            return self.pattern.search(pathname) is not None
        return self.pattern.fullmatch(pathname) is not None


@dataclass(frozen=True)
class DomainRule:
    """Allow rule that matches an exact domain and optional subdomains."""

    name: str
    domain: str
    include_subdomains: bool
    methods: tuple[str, ...]
    pathname_filter: PathnameFilter | None = None

    def matches(self, host: str, method: str, pathname: str = "/") -> bool:
        """Return whether this rule allows the given host, method, and pathname."""
        if not method_matches(self.methods, method):
            return False

        host = normalize_host(host)
        domain = normalize_host(self.domain)

        host_matches = host == domain or (
            self.include_subdomains and host.endswith(f".{domain}")
        )
        if not host_matches:
            return False

        return self.pathname_filter is None or self.pathname_filter.matches(pathname)


@dataclass(frozen=True)
class RegexRule:
    """Allow rule that matches hostnames with a regular expression."""

    name: str
    pattern: re.Pattern[str]
    methods: tuple[str, ...]
    pathname_filter: PathnameFilter | None = None

    def matches(self, host: str, method: str, pathname: str = "/") -> bool:
        """Return whether this regex rule allows the given host, method, and pathname."""
        if not method_matches(self.methods, method):
            return False

        if self.pattern.search(normalize_host(host)) is None:
            return False

        return self.pathname_filter is None or self.pathname_filter.matches(pathname)


Rule = DomainRule | RegexRule


@dataclass(frozen=True)
class TextToken:
    """Literal text segment in a pathname pattern."""

    value: str


@dataclass(frozen=True)
class ParamToken:
    """Named pathname segment parameter token."""

    name: str


@dataclass(frozen=True)
class WildcardToken:
    """Named pathname wildcard token that can span multiple characters."""

    name: str


@dataclass(frozen=True)
class GroupToken:
    """Optional group of pathname pattern tokens."""

    tokens: list["PathnamePatternToken"]


FlatPathnamePatternToken = TextToken | ParamToken | WildcardToken
PathnamePatternToken = FlatPathnamePatternToken | GroupToken
DEFAULT_ALLOWED_METHODS = ("GET", "HEAD")
ANY_METHOD = "ANY"
ALLOW_RULE_KEYS = {
    "domain",
    "domain_regex",
    "include_subdomains",
    "methods",
    "pathname_regex",
    "pathname_pattern",
}


class RequestLike(Protocol):
    """Subset of mitmproxy request attributes used by the addon."""

    pretty_host: str
    host: str
    method: str
    pretty_url: str


class FlowLike(Protocol):
    """Subset of mitmproxy flow behavior used by the addon."""

    request: RequestLike

    def kill(self) -> None:
        """Terminate the in-flight request flow immediately."""
        ...


def normalize_host(host: str) -> str:
    """Normalize hostnames before rule matching."""
    return host.strip().rstrip(".").lower()


def normalize_method(method: str) -> str:
    """Normalize HTTP methods before rule matching."""
    return method.strip().upper()


def method_matches(allowed_methods: tuple[str, ...], method: str) -> bool:
    """Return whether a request method is included in an allow rule method set."""
    normalized_method = normalize_method(method)
    return ANY_METHOD in allowed_methods or normalized_method in allowed_methods


def request_pathname(url: str) -> str:
    """Return the URL pathname, excluding query string and fragment."""
    pathname = urlsplit(url).path
    return pathname or "/"


def is_toml_array(value: object) -> TypeGuard[Sequence[object]]:
    """Return whether a TOML value is an array."""
    return isinstance(value, list)


def is_toml_table(value: object) -> TypeGuard[dict[str, object]]:
    """Return whether a TOML value is a table."""
    return isinstance(value, dict)


def require_string(rule: dict[str, object], key: str, index: int) -> str:
    """Return a required non-empty string value from an allow rule table."""
    value = rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"allow rule #{index}: {key!r} must be a non-empty string")
    return value


def validate_allowed_keys(
    rule: dict[str, object], allowed_keys: set[str], index: int
) -> None:
    """Reject unknown keys in an allow rule table."""
    extra_keys = set(rule) - allowed_keys
    if extra_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_keys))
        raise ValueError(f"allow rule #{index}: unsupported key(s): {keys}")


def rule_name(name: str, pathname_filter: PathnameFilter | None) -> str:
    """Build the human-readable rule name used in logs."""
    if pathname_filter is None:
        return name
    return f"{name}, {pathname_filter.name}"


def is_parameter_name_start(char: str | None) -> bool:
    """Return whether a character can start a pathname parameter name."""
    return char is not None and (char == "$" or char == "_" or char.isalpha())


def is_parameter_name_continue(char: str | None) -> bool:
    """Return whether a character can continue a pathname parameter name."""
    return char is not None and (
        char == "$"
        or char == "_"
        or char == "\u200c"
        or char == "\u200d"
        or char.isalpha()
        or char.isdigit()
    )


def parse_pathname_pattern_tokens(pattern: str) -> list[PathnamePatternToken]:
    """Parse a URLPattern-style pathname pattern into structured tokens."""
    chars = list(pattern)
    index = 0

    def current_char() -> str | None:
        """Return the current pattern character without advancing."""
        if index >= len(chars):
            return None
        return chars[index]

    def consume_until(end: str) -> list[PathnamePatternToken]:
        """Consume tokens until the requested terminator is reached."""
        nonlocal index
        output: list[PathnamePatternToken] = []
        path = ""

        def write_path() -> None:
            """Flush accumulated literal pathname text into the token stream."""
            nonlocal path
            if not path:
                return
            output.append(TextToken(path))
            path = ""

        while index < len(chars):
            value = chars[index]
            index += 1

            if value == end:
                write_path()
                return output

            if value == "\\":
                if index == len(chars):
                    raise ValueError(f"unexpected end after \\ at index {index}")
                path += chars[index]
                index += 1
                continue

            if value == ":" or value == "*":
                token_type = "param" if value == ":" else "wildcard"
                name = ""

                if is_parameter_name_start(current_char()):
                    while is_parameter_name_continue(current_char()):
                        name += chars[index]
                        index += 1
                elif current_char() == '"':
                    quote_start = index
                    index += 1
                    while index < len(chars):
                        quoted = chars[index]
                        index += 1
                        if quoted == '"':
                            break
                        if quoted == "\\":
                            if index == len(chars):
                                raise ValueError(
                                    f"unexpected end after \\ at index {index}"
                                )
                            quoted = chars[index]
                            index += 1
                        name += quoted
                    else:
                        raise ValueError(f"unterminated quote at index {quote_start}")

                if not name:
                    raise ValueError(f"missing parameter name at index {index}")

                write_path()
                if token_type == "param":
                    output.append(ParamToken(name))
                else:
                    output.append(WildcardToken(name))
                continue

            if value == "{":
                write_path()
                output.append(GroupToken(consume_until("}")))
                continue

            if value in "}()[]+?!":
                raise ValueError(f"unexpected {value} at index {index - 1}")

            path += value

        if end:
            raise ValueError(f"unexpected end at index {index}, expected {end}")

        write_path()
        return output

    return consume_until("")


def flatten_pathname_pattern_tokens(
    tokens: list[PathnamePatternToken],
) -> list[list[FlatPathnamePatternToken]]:
    """Expand optional groups into all flat pathname token sequences."""
    sequences: list[list[FlatPathnamePatternToken]] = [[]]

    for token in tokens:
        if not isinstance(token, GroupToken):
            for sequence in sequences:
                sequence.append(token)
            continue

        group_sequences = flatten_pathname_pattern_tokens(token.tokens)
        included = [
            sequence + group_sequence
            for sequence in sequences
            for group_sequence in group_sequences
        ]
        sequences = included + sequences
        if len(sequences) > 256:
            raise ValueError("too many path combinations")

    return sequences


def pathname_tokens_to_regex_source(tokens: list[FlatPathnamePatternToken]) -> str:
    """Convert a flat pathname token sequence into regex source text."""
    source = ""
    for token in tokens:
        if isinstance(token, TextToken):
            source += re.escape(token.value)
        elif isinstance(token, ParamToken):
            source += "([^/]+)"
        else:
            source += "(.+)"
    return source


def compile_pathname_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a URLPattern-style pathname pattern to a case-sensitive regex."""
    tokens = parse_pathname_pattern_tokens(pattern)
    sequences = flatten_pathname_pattern_tokens(tokens)
    source = "|".join(
        pathname_tokens_to_regex_source(sequence) for sequence in sequences
    )
    trailing = "" if pattern.endswith("/") else "/?"
    return re.compile(f"(?:{source}){trailing}")


def parse_pathname_filter(rule: dict[str, object], index: int) -> PathnameFilter | None:
    """Parse an optional pathname matcher from an allow rule table."""
    has_pathname_regex = "pathname_regex" in rule
    has_pathname_pattern = "pathname_pattern" in rule

    if has_pathname_regex and has_pathname_pattern:
        raise ValueError(
            f"allow rule #{index}: cannot set both 'pathname_regex' and 'pathname_pattern'"
        )

    if has_pathname_regex:
        pathname_regex = require_string(rule, "pathname_regex", index)
        try:
            pattern = re.compile(pathname_regex)
        except re.error as exc:
            raise ValueError(
                f"allow rule #{index}: invalid pathname_regex {pathname_regex!r}: {exc}"
            ) from exc
        return PathnameFilter(
            name=f"pathname_regex {pathname_regex!r}",
            pattern=pattern,
            uses_search=True,
            kind="pathname_regex",
            source=pathname_regex,
        )

    if has_pathname_pattern:
        pathname_pattern = require_string(rule, "pathname_pattern", index)
        try:
            pattern = compile_pathname_pattern(pathname_pattern)
        except ValueError as exc:
            raise ValueError(
                f"allow rule #{index}: invalid pathname_pattern {pathname_pattern!r}: {exc}"
            ) from exc
        return PathnameFilter(
            name=f"pathname_pattern {pathname_pattern!r}",
            pattern=pattern,
            uses_search=False,
            kind="pathname_pattern",
            source=pathname_pattern,
        )

    return None


def parse_methods(rule: dict[str, object], index: int) -> tuple[str, ...]:
    """Parse and normalize the HTTP methods allowed by a rule."""
    if "methods" not in rule:
        return DEFAULT_ALLOWED_METHODS

    value = rule["methods"]
    if isinstance(value, str):
        method = normalize_method(value)
        if method == ANY_METHOD:
            return (ANY_METHOD,)
        raise ValueError(f"allow rule #{index}: string 'methods' value must be 'ANY'")

    if not is_toml_array(value) or not value:
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
    """Load and validate allow rules from a single TOML file."""
    with path.open("rb") as file:
        config_value = tomllib.load(file)

    if not is_toml_table(config_value):
        raise ValueError("top-level TOML value must be a table")

    extra_top_level_keys = set(config_value) - {"allow"}
    if extra_top_level_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_top_level_keys))
        raise ValueError(f"unsupported top-level key(s): {keys}")

    allow_rules_value = config_value.get("allow", [])
    if not is_toml_array(allow_rules_value):
        raise ValueError("'allow' must be a list of tables")

    parsed_rules: list[Rule] = []
    for index, rule in enumerate(allow_rules_value, start=1):
        if not is_toml_table(rule):
            raise ValueError(f"allow rule #{index}: rule must be a table")

        validate_allowed_keys(rule, ALLOW_RULE_KEYS, index)

        has_domain = "domain" in rule
        has_domain_regex = "domain_regex" in rule
        if has_domain and has_domain_regex:
            raise ValueError(
                f"allow rule #{index}: cannot set both 'domain' and 'domain_regex'"
            )
        if not has_domain and not has_domain_regex:
            raise ValueError(
                f"allow rule #{index}: exactly one of 'domain' or 'domain_regex' is required"
            )

        methods = parse_methods(rule, index)
        pathname_filter = parse_pathname_filter(rule, index)

        if has_domain:
            validate_allowed_keys(
                rule,
                {
                    "domain",
                    "include_subdomains",
                    "methods",
                    "pathname_regex",
                    "pathname_pattern",
                },
                index,
            )
            domain = require_string(rule, "domain", index)
            include_subdomains = rule.get("include_subdomains", False)
            if not isinstance(include_subdomains, bool):
                raise ValueError(
                    f"allow rule #{index}: 'include_subdomains' must be a boolean"
                )
            normalized_domain = normalize_host(domain)
            parsed_rules.append(
                DomainRule(
                    name=rule_name(f"domain {normalized_domain}", pathname_filter),
                    domain=normalized_domain,
                    include_subdomains=include_subdomains,
                    methods=methods,
                    pathname_filter=pathname_filter,
                )
            )
        else:
            validate_allowed_keys(
                rule,
                {"domain_regex", "methods", "pathname_regex", "pathname_pattern"},
                index,
            )
            domain_regex = require_string(rule, "domain_regex", index)
            try:
                pattern = re.compile(domain_regex, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"allow rule #{index}: invalid domain_regex {domain_regex!r}: {exc}"
                ) from exc
            parsed_rules.append(
                RegexRule(
                    name=rule_name(f"domain_regex {domain_regex!r}", pathname_filter),
                    pattern=pattern,
                    methods=methods,
                    pathname_filter=pathname_filter,
                )
            )

    return parsed_rules


def describe_rule(index: int, rule: Rule) -> str:
    """Return a log-friendly description of a parsed allow rule."""
    methods = ",".join(rule.methods)
    if isinstance(rule, DomainRule):
        parts = [
            f"allow rule #{index}:",
            f"domain={rule.domain!r}",
            f"include_subdomains={rule.include_subdomains}",
            f"methods={methods}",
        ]
    else:
        parts = [
            f"allow rule #{index}:",
            f"domain_regex={rule.pattern.pattern!r}",
            f"methods={methods}",
        ]

    if rule.pathname_filter is not None:
        pathname_filter = rule.pathname_filter
        parts.append(f"{pathname_filter.kind}={pathname_filter.source!r}")
        if pathname_filter.kind == "pathname_pattern":
            parts.append(f"compiled_regex={pathname_filter.pattern.pattern!r}")

    return " ".join(parts)


def load_rules(path: Path = RULES_DIR) -> list[Rule]:
    """Load all TOML allow rules from a directory."""
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
    """mitmproxy addon that enforces mitmwall hostname allow rules."""

    def __init__(self) -> None:
        """Initialize addon state and configure logging."""
        self.rules: list[Rule] = []
        self.rule_descriptions: tuple[str, ...] = ()
        setup_logging()

    def load(self, _loader: object) -> None:
        """Handle mitmproxy addon load events by loading the current rules."""
        LOGGER.info("addon loaded")
        self.reload_rules()

    def running(self) -> None:
        """Reload rules once mitmproxy has finished starting up."""
        self.reload_rules()

    def configure(self, _updated: set[str]) -> None:
        """Reload rules after mitmproxy configuration changes."""
        # Reload on mitmproxy config changes. This gives operators a lightweight
        # way to pick up edits with `:set`/reload-like workflows without restart.
        self.reload_rules()

    def reload_rules(self) -> None:
        """Load rules from disk and update logged descriptions when they change."""
        try:
            rules = load_rules()
        except Exception as exc:
            # Fail closed: if the allowlist is missing or invalid, block all traffic.
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
        """Allow matching requests and terminate flows that do not match any rule."""
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
        """Return whether any loaded rule allows the given request details."""
        normalized_host = normalize_host(host)
        normalized_method = normalize_method(method)
        for rule in self.rules:
            if rule.matches(normalized_host, normalized_method, pathname):
                return MatchResult(allowed=True, rule_name=rule.name)
        return MatchResult(allowed=False)


addons = [Mitmwall()]
