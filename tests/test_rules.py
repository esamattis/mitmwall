"""
Unit tests for allow-rule parsing and request header injections.
"""

import re
import tempfile
import unittest
from pathlib import Path
from typing import final, override

from mitmproxy_addon.addon import (
    DNSFlowLike,
    DNSQuestionLike,
    DNSRequestLike,
    FlowLike,
    HeadersLike,
    Mitmwall,
    RequestLike,
)
from mitmproxy_addon.pathname_pattern import compile_pathname_pattern
from mitmproxy_addon.rules import (
    DomainRule,
    InjectedHeader,
    PathnameFilter,
    RegexRule,
    describe_rule,
    load_rules,
    parse_rules_file,
)


@final
class FakeHeaders(HeadersLike):
    """
    Minimal mutable header container for addon unit tests.
    """

    _values: dict[str, str]

    def __init__(self) -> None:
        """
        Initialize an empty fake header container.
        """

        self._values = {}

    @override
    def __setitem__(self, key: str, value: str, /) -> None:
        """
        Set or replace a fake header value.
        """

        self._values[key] = value

    @override
    def __getitem__(self, key: str, /) -> str:
        """
        Return a fake header value.
        """

        return self._values[key]


@final
class FakeRequest:
    """
    Minimal request object for addon unit tests.
    """

    pretty_host: str
    host: str
    method: str
    pretty_url: str
    headers: HeadersLike

    def __init__(self, host: str, method: str, url: str) -> None:
        """
        Initialize a fake request with mutable headers.
        """

        self.pretty_host = host
        self.host = host
        self.method = method
        self.pretty_url = url
        self.headers = FakeHeaders()


@final
class FakeFlow(FlowLike):
    """
    Minimal flow object for addon unit tests.
    """

    request: RequestLike
    killed: bool

    def __init__(self, request: RequestLike) -> None:
        """
        Initialize a fake flow that records whether it was killed.
        """

        self.request = request
        self.killed = False

    @override
    def kill(self) -> None:
        """
        Record that the addon blocked this flow.
        """

        self.killed = True


@final
class FakeDNSQuestion(DNSQuestionLike):
    """
    Minimal DNS question object for addon unit tests.
    """

    name: str

    def __init__(self, name: str) -> None:
        """
        Initialize a fake DNS question with a hostname.
        """

        self.name = name


@final
class FakeDNSRequest(DNSRequestLike):
    """
    Minimal DNS request object for addon unit tests.
    """

    question: DNSQuestionLike | None

    def __init__(self, name: str | None) -> None:
        """
        Initialize a fake DNS request with an optional question.
        """

        self.question = None if name is None else FakeDNSQuestion(name)

    @override
    def fail(self, response_code: int) -> object:
        """
        Return a fake DNS error response marker.
        """

        return ("failed", response_code)


@final
class FakeDNSFlow(DNSFlowLike):
    """
    Minimal DNS flow object for addon unit tests.
    """

    request: DNSRequestLike
    response: object | None

    def __init__(self, name: str | None) -> None:
        """
        Initialize a fake DNS flow without a response.
        """

        self.request = FakeDNSRequest(name)
        self.response = None


class RuleParsingTests(unittest.TestCase):
    """
    Verify allow-rule parsing behavior, including load order.
    """

    def test_parse_rules_file_accepts_inject_headers(self) -> None:
        """
        Parse an inject_headers rule into structured header definitions.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
inject_headers = [
    { name = "Authorization", value = "Secret" },
    { name = "X-Mitmwall-Test", value = "enabled" },
]
""".strip()
        )

        self.assertIsInstance(rule, DomainRule)
        self.assertEqual(
            rule.inject_headers,
            (
                InjectedHeader(name="Authorization", value="Secret"),
                InjectedHeader(name="X-Mitmwall-Test", value="enabled"),
            ),
        )

    def test_parse_rules_file_rejects_string_inject_headers_items(self) -> None:
        """
        Reject inject_headers items that are not TOML tables.
        """

        with self.assertRaisesRegex(ValueError, "must be a table"):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
inject_headers = ["Authorization: Secret"]
""".strip()
            )

    def test_parse_rules_file_rejects_legacy_inject_header(self) -> None:
        """
        Reject the legacy inject_header key.
        """

        with self.assertRaisesRegex(
            ValueError, r"unsupported key\(s\): 'inject_header'"
        ):
            _rule = self._parse_single_rule(
                """
[[allow]]
domain = "pie.dev"
inject_header = "Authorization: Secret"
""".strip()
            )

    def test_describe_rule_redacts_injected_header_values(self) -> None:
        """
        Log rule descriptions without exposing injected header secrets.
        """

        rule = self._parse_single_rule(
            """
[[allow]]
domain = "pie.dev"
inject_headers = [
    { name = "Authorization", value = "Secret" },
    { name = "X-Mitmwall-Test", value = "enabled" },
]
""".strip()
        )

        description = describe_rule(1, rule)

        self.assertIn(
            "inject_header_names=['Authorization', 'X-Mitmwall-Test']",
            description,
        )
        self.assertNotIn("Secret", description)
        self.assertNotIn("enabled", description)

    def test_load_rules_sorts_files_alphabetically(self) -> None:
        """
        Load TOML rule files in alphabetical filename order.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir)
            _ = (rules_dir / "20-second.toml").write_text(
                '[[allow]]\ndomain = "second.example"\n',
                encoding="utf-8",
            )
            _ = (rules_dir / "10-first.toml").write_text(
                '[[allow]]\ndomain = "first.example"\n',
                encoding="utf-8",
            )

            rules = load_rules(rules_dir)

        self.assertTrue(all(isinstance(rule, DomainRule) for rule in rules))
        self.assertEqual(
            [rule.domain for rule in rules if isinstance(rule, DomainRule)],
            ["first.example", "second.example"],
        )

    def test_load_rules_ignores_hidden_toml_files(self) -> None:
        """
        Skip dot-prefixed TOML files when loading a rules directory.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            rules_dir = Path(temp_dir)
            _ = (rules_dir / ".10-hidden.toml").write_text(
                '[[allow]]\ndomain = "hidden.example"\n',
                encoding="utf-8",
            )
            _ = (rules_dir / "20-visible.toml").write_text(
                '[[allow]]\ndomain = "visible.example"\n',
                encoding="utf-8",
            )

            rules = load_rules(rules_dir)

        self.assertTrue(all(isinstance(rule, DomainRule) for rule in rules))
        self.assertEqual(
            [rule.domain for rule in rules if isinstance(rule, DomainRule)],
            ["visible.example"],
        )

    def _parse_single_rule(self, content: str) -> DomainRule:
        """
        Parse one domain rule from temporary TOML content.
        """

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "rules.toml"
            _ = path.write_text(content, encoding="utf-8")
            rules = parse_rules_file(path)

        self.assertEqual(len(rules), 1)
        rule = rules[0]
        if not isinstance(rule, DomainRule):
            raise AssertionError(f"expected DomainRule, got {type(rule)!r}")
        return rule


class DNSAddonTests(unittest.TestCase):
    """
    Verify addon behavior for DNS allowlist enforcement.
    """

    def test_dns_request_allows_pathname_and_method_restricted_rule_domain(
        self,
    ) -> None:
        """
        Allow DNS for a matching domain even when HTTP filters would not match.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain pie.dev, pathname_pattern '/headers'",
                domain="pie.dev",
                include_subdomains=False,
                methods=("POST",),
                pathname_filter=PathnameFilter(
                    name="pathname_pattern '/headers'",
                    pattern=compile_pathname_pattern("/headers"),
                    uses_search=False,
                    kind="pathname_pattern",
                    source="/headers",
                ),
            )
        ]
        flow = FakeDNSFlow("pie.dev")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_allows_matching_domain_regex(self) -> None:
        """
        Allow DNS for a hostname matching a domain_regex rule.
        """

        addon = Mitmwall()
        addon.rules = [
            RegexRule(
                name="domain_regex '^api[.]example[.]com$'",
                pattern=re.compile(r"^api[.]example[.]com$", re.IGNORECASE),
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("api.example.com")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_refuses_unmatched_domain_regex(self) -> None:
        """
        Refuse DNS for a hostname that does not match a domain_regex rule.
        """

        addon = Mitmwall()
        addon.rules = [
            RegexRule(
                name="domain_regex '^api[.]example[.]com$'",
                pattern=re.compile(r"^api[.]example[.]com$", re.IGNORECASE),
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("www.example.com")

        addon.dns_request(flow)

        self.assertEqual(flow.response, ("failed", 5))

    def test_dns_request_refuses_unmatched_domain(self) -> None:
        """
        Refuse DNS queries that do not match any rule hostname.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain pie.dev",
                domain="pie.dev",
                include_subdomains=False,
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)

        self.assertEqual(flow.response, ("failed", 5))

    def test_dns_request_passes_unmatched_domain_when_block_dns_is_false(self) -> None:
        """
        Allow unmatched DNS queries through when DNS blocking is disabled.
        """

        addon = Mitmwall()
        addon.block_dns = False
        addon.rules = [
            DomainRule(
                name="domain pie.dev",
                domain="pie.dev",
                include_subdomains=False,
                methods=("GET",),
            )
        ]
        flow = FakeDNSFlow("blocked.example")

        addon.dns_request(flow)

        self.assertIsNone(flow.response)

    def test_dns_request_without_question_passes_when_block_dns_is_false(self) -> None:
        """
        Allow malformed DNS requests through when DNS blocking is disabled.
        """

        addon = Mitmwall()
        addon.block_dns = False
        flow = FakeDNSFlow(None)

        addon.dns_request(flow)

        self.assertIsNone(flow.response)


class HeaderInjectionAddonTests(unittest.TestCase):
    """
    Verify addon behavior when matching rules inject headers.
    """

    def test_request_injects_headers_for_matching_rule(self) -> None:
        """
        Inject the configured headers into an allowed matching request.
        """

        addon = Mitmwall()
        addon.rules = [
            DomainRule(
                name="domain pie.dev",
                domain="pie.dev",
                include_subdomains=False,
                methods=("GET",),
            ),
            DomainRule(
                name="domain pie.dev, pathname_pattern '/headers'",
                domain="pie.dev",
                include_subdomains=False,
                methods=("GET",),
                pathname_filter=PathnameFilter(
                    name="pathname_pattern '/headers'",
                    pattern=compile_pathname_pattern("/headers"),
                    uses_search=False,
                    kind="pathname_pattern",
                    source="/headers",
                ),
                inject_headers=(
                    InjectedHeader(
                        name="Authorization",
                        value="Secret",
                    ),
                    InjectedHeader(
                        name="X-Mitmwall-Test",
                        value="enabled",
                    ),
                ),
            ),
        ]

        flow = FakeFlow(FakeRequest("pie.dev", "GET", "https://pie.dev/headers"))

        addon.request(flow)

        self.assertFalse(flow.killed)
        self.assertEqual(flow.request.headers["Authorization"], "Secret")
        self.assertEqual(flow.request.headers["X-Mitmwall-Test"], "enabled")


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
