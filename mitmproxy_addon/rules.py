"""
Allow rule parsing and matching for the mitmwall addon.
"""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard, cast
from urllib.parse import urlsplit

import tomllib

from .constants import ALLOW_RULE_KEYS, ANY_METHOD, DEFAULT_ALLOWED_METHODS, RULES_DIR
from .pathname_pattern import compile_pathname_pattern

HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.\^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class InjectedHeader:
    """
    Header name and value to add to an allowed upstream request.
    """

    name: str
    value: str


@dataclass(frozen=True)
class MatchResult:
    """
    Result of evaluating a request against the allow rules.
    """

    allowed: bool
    rule_name: str | None = None
    inject_headers: tuple[InjectedHeader, ...] = ()


@dataclass(frozen=True)
class PathnameFilter:
    """
    Compiled pathname matcher attached to an allow rule.
    """

    name: str
    pattern: re.Pattern[str]
    uses_search: bool
    kind: str
    source: str

    def matches(self, pathname: str) -> bool:
        """
        Return whether the pathname satisfies this filter.
        """

        if self.uses_search:
            return self.pattern.search(pathname) is not None
        return self.pattern.fullmatch(pathname) is not None


@dataclass(frozen=True)
class DomainRule:
    """
    Allow rule that matches a domain by exact name (with optional subdomains) or regex.
    """

    name: str
    domain: tuple[str, ...] | tuple[re.Pattern[str], ...]
    include_subdomains: bool
    methods: tuple[str, ...]
    pathname_filters: tuple[PathnameFilter, ...] = ()
    inject_headers: tuple[InjectedHeader, ...] = ()

    def matches_host(self, host: str) -> bool:
        """
        Return whether this rule would allow the given hostname before HTTP filters.
        """

        normalized = normalize_host(host)
        if not self.domain:
            return False
        if isinstance(self.domain[0], re.Pattern):
            patterns = cast("tuple[re.Pattern[str], ...]", self.domain)
            return any(
                pattern.search(normalized) is not None
                for pattern in patterns
            )
        domains = cast("tuple[str, ...]", self.domain)
        return any(
            normalized == normalize_host(d)
            or (self.include_subdomains and normalized.endswith(f".{normalize_host(d)}"))
            for d in domains
        )

    def matches(self, host: str, method: str, pathname: str = "/") -> bool:
        """
        Return whether this rule allows the given host, method, and pathname.
        """

        if not method_matches(self.methods, method):
            return False

        if not self.matches_host(host):
            return False

        return not self.pathname_filters or any(
            f.matches(pathname) for f in self.pathname_filters
        )


def normalize_host(host: str) -> str:
    """
    Normalize hostnames before rule matching.
    """

    return host.strip().rstrip(".").lower()


def normalize_method(method: str) -> str:
    """
    Normalize HTTP methods before rule matching.
    """

    return method.strip().upper()


def method_matches(allowed_methods: tuple[str, ...], method: str) -> bool:
    """
    Return whether a request method is included in an allow rule method set.
    """

    normalized_method = normalize_method(method)
    return ANY_METHOD in allowed_methods or normalized_method in allowed_methods


def request_pathname(url: str) -> str:
    """
    Return the URL pathname, excluding query string and fragment.
    """

    pathname = urlsplit(url).path
    return pathname or "/"


def is_toml_array(value: object) -> TypeGuard[Sequence[object]]:
    """
    Return whether a TOML value is an array.
    """

    return isinstance(value, list)


def get_toml_array(raw_value: object, key: str, index: int) -> list[str]:
    """
    Normalize a TOML string or array-of-strings value into a list of strings.
    """

    if isinstance(raw_value, str):
        return [raw_value]
    if is_toml_array(raw_value) and raw_value:
        items: list[str] = []
        for item_index, item in enumerate(raw_value, start=1):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(
                    f"allow rule #{index}: {key} item #{item_index} must be a non-empty string"
                )
            items.append(item)
        return items
    raise ValueError(
        f"allow rule #{index}: {key!r} must be a non-empty string or a non-empty list"
    )


def is_toml_table(value: object) -> TypeGuard[dict[str, object]]:
    """
    Return whether a TOML value is a table.
    """

    return isinstance(value, dict)


def validate_allowed_keys(
    rule: dict[str, object], allowed_keys: set[str], index: int
) -> None:
    """
    Reject unknown keys in an allow rule table.
    """

    extra_keys = set(rule) - allowed_keys
    if extra_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_keys))
        raise ValueError(f"allow rule #{index}: unsupported key(s): {keys}")


def rule_name(name: str, pathname_filters: tuple[PathnameFilter, ...]) -> str:
    """
    Build the human-readable rule name used in logs.
    """

    if not pathname_filters:
        return name
    filter_names = ", ".join(f.name for f in pathname_filters)
    return f"{name}, {filter_names}"


def parse_pathname_filter_value(
    raw_value: object,
    key: str,
    index: int,
    compile_func: Callable[[str], re.Pattern[str]],
    uses_search: bool,
) -> list[PathnameFilter]:
    """
    Parse a pathname_regex or pathname_pattern value into a list of PathnameFilters.
    """

    items_list = get_toml_array(raw_value, key, index)

    filters: list[PathnameFilter] = []
    for item in items_list:
        try:
            compiled = compile_func(item)
        except (re.error, ValueError) as exc:
            raise ValueError(
                f"allow rule #{index}: invalid {key} {item!r}: {exc}"
            ) from exc
        filters.append(
            PathnameFilter(
                name=f"{key} {item!r}",
                pattern=compiled,
                uses_search=uses_search,
                kind=key,
                source=item,
            )
        )
    return filters


def parse_pathname_filters(
    rule: dict[str, object], index: int
) -> tuple[PathnameFilter, ...]:
    """
    Parse optional pathname matchers from an allow rule table.
    """

    filters: list[PathnameFilter] = []

    if "pathname_regex" in rule:
        filters.extend(
            parse_pathname_filter_value(
                rule["pathname_regex"],
                "pathname_regex",
                index,
                re.compile,
                uses_search=True,
            )
        )

    if "pathname_pattern" in rule:
        filters.extend(
            parse_pathname_filter_value(
                rule["pathname_pattern"],
                "pathname_pattern",
                index,
                compile_pathname_pattern,
                uses_search=False,
            )
        )

    return tuple(filters)


def parse_methods(rule: dict[str, object], index: int) -> tuple[str, ...]:
    """
    Parse and normalize the HTTP methods allowed by a rule.
    """

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


def parse_injected_header(
    header: dict[str, object], error_prefix: str
) -> InjectedHeader:
    """
    Parse one configured upstream header injection table.
    """

    extra_keys = set(header) - {"name", "value"}
    if extra_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_keys))
        raise ValueError(f"{error_prefix} has unsupported key(s): {keys}")

    name_value = header.get("name")
    if not isinstance(name_value, str) or not name_value.strip():
        raise ValueError(f"{error_prefix} 'name' must be a non-empty string")
    name = name_value.strip()
    if HEADER_NAME_PATTERN.fullmatch(name) is None:
        raise ValueError(f"{error_prefix} has invalid header name {name!r}")

    value = header.get("value")
    if not isinstance(value, str):
        raise ValueError(f"{error_prefix} 'value' must be a string")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{error_prefix} value must not contain CR or LF")

    return InjectedHeader(name=name, value=value)


def parse_inject_headers(
    rule: dict[str, object], index: int
) -> tuple[InjectedHeader, ...]:
    """
    Parse optional upstream header injections from an allow rule table.
    """

    key = "inject_headers"
    if key not in rule:
        return ()

    value = rule[key]
    if not is_toml_array(value) or not value:
        raise ValueError(f"allow rule #{index}: {key!r} must be a non-empty list")

    headers: list[InjectedHeader] = []
    for header_index, header_value in enumerate(value, start=1):
        if not is_toml_table(header_value):
            raise ValueError(
                f"allow rule #{index}: {key!r} item #{header_index} must be a table"
            )
        headers.append(
            parse_injected_header(
                header_value,
                f"allow rule #{index}: {key!r} item #{header_index}",
            )
        )

    return tuple(headers)


def parse_domain_value(
    rule: dict[str, object], index: int
) -> tuple[str, ...]:
    """
    Parse a domain value that may be a string or list of strings.
    """

    raw_value = rule.get("domain")
    items = get_toml_array(raw_value, "domain", index)

    return tuple(normalize_host(item) for item in items)


def parse_domain_regex_value(
    rule: dict[str, object], index: int
) -> tuple[re.Pattern[str], ...]:
    """
    Parse a domain_regex value that may be a string or list of strings.
    """

    raw_value = rule.get("domain_regex")
    items = get_toml_array(raw_value, "domain_regex", index)

    patterns: list[re.Pattern[str]] = []
    for item in items:
        try:
            patterns.append(re.compile(item, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(
                f"allow rule #{index}: invalid domain_regex {item!r}: {exc}"
            ) from exc
    return tuple(patterns)


def parse_rules_text(text: str) -> list[DomainRule]:
    """
    Load and validate allow rules from a TOML string.
    """

    config_value = tomllib.loads(text)

    if not is_toml_table(config_value):
        raise ValueError("top-level TOML value must be a table")

    extra_top_level_keys = set(config_value) - {"allow"}
    if extra_top_level_keys:
        keys = ", ".join(sorted(repr(key) for key in extra_top_level_keys))
        raise ValueError(f"unsupported top-level key(s): {keys}")

    allow_rules_value = config_value.get("allow", [])
    if not is_toml_array(allow_rules_value):
        raise ValueError("'allow' must be a list of tables")

    parsed_rules: list[DomainRule] = []
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
        pathname_filters = parse_pathname_filters(rule, index)
        inject_headers = parse_inject_headers(rule, index)

        if has_domain:
            validate_allowed_keys(
                rule,
                {
                    "domain",
                    "include_subdomains",
                    "inject_headers",
                    "methods",
                    "pathname_regex",
                    "pathname_pattern",
                },
                index,
            )
            domains = parse_domain_value(rule, index)
            include_subdomains = rule.get("include_subdomains", False)
            if not isinstance(include_subdomains, bool):
                raise ValueError(
                    f"allow rule #{index}: 'include_subdomains' must be a boolean"
                )
            domain_label = ", ".join(domains)
            parsed_rules.append(
                DomainRule(
                    name=rule_name(f"domain {domain_label}", pathname_filters),
                    domain=domains,
                    include_subdomains=include_subdomains,
                    methods=methods,
                    pathname_filters=pathname_filters,
                    inject_headers=inject_headers,
                )
            )
        else:
            validate_allowed_keys(
                rule,
                {
                    "domain_regex",
                    "inject_headers",
                    "methods",
                    "pathname_regex",
                    "pathname_pattern",
                },
                index,
            )
            patterns = parse_domain_regex_value(rule, index)
            regex_label = ", ".join(p.pattern for p in patterns)
            parsed_rules.append(
                DomainRule(
                    name=rule_name(f"domain_regex {regex_label}", pathname_filters),
                    domain=patterns,
                    include_subdomains=False,
                    methods=methods,
                    pathname_filters=pathname_filters,
                    inject_headers=inject_headers,
                )
            )

    return parsed_rules


def parse_rules_file(path: Path) -> list[DomainRule]:
    """
    Load and validate allow rules from a single TOML file.
    """

    with path.open("rb") as file:
        text = file.read().decode("utf-8")
    return parse_rules_text(text)


def describe_rule(index: int, rule: DomainRule) -> str:
    """
    Return a log-friendly description of a parsed allow rule.
    """

    methods = ",".join(rule.methods)
    if rule.domain and isinstance(rule.domain[0], re.Pattern):
        regex_patterns = cast("tuple[re.Pattern[str], ...]", rule.domain)
        pattern_strs = [p.pattern for p in regex_patterns]
        parts = [
            f"allow rule #{index}:",
            f"domain_regex={pattern_strs!r}",
            f"methods={methods}",
        ]
    else:
        domain_strs = cast("tuple[str, ...]", rule.domain)
        parts = [
            f"allow rule #{index}:",
            f"domain={list(domain_strs)!r}",
            f"include_subdomains={rule.include_subdomains}",
            f"methods={methods}",
        ]

    if rule.pathname_filters:
        for pathname_filter in rule.pathname_filters:
            parts.append(f"{pathname_filter.kind}={pathname_filter.source!r}")
            if pathname_filter.kind == "pathname_pattern":
                parts.append(f"compiled_regex={pathname_filter.pattern.pattern!r}")

    if rule.inject_headers:
        header_names = [header.name for header in rule.inject_headers]
        parts.append(f"inject_header_names={header_names!r}")

    return " ".join(parts)


def load_rules(path: Path = RULES_DIR) -> list[DomainRule]:
    """
    Load all TOML allow rules from a directory in alphabetical filename order.
    """

    if not path.exists():
        raise FileNotFoundError(f"rules directory does not exist: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"rules path is not a directory: {path}")

    parsed_rules: list[DomainRule] = []
    rule_files = sorted(
        (
            child
            for child in path.iterdir()
            if child.is_file()
            and not child.name.startswith(".")
            and child.suffix == ".toml"
        ),
        key=lambda child: child.name,
    )
    for rule_file in rule_files:
        try:
            parsed_rules.extend(parse_rules_file(rule_file))
        except Exception as exc:
            raise ValueError(f"failed to load {rule_file}: {exc}") from exc

    return parsed_rules
