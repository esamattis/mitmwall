"""
Unit tests for pathname pattern parsing and compilation.
"""

import unittest

from mitmproxy_addon.pathname_pattern import (
    GroupToken,
    ParamToken,
    TextToken,
    WildcardToken,
    compile_pathname_pattern,
    flatten_pathname_pattern_tokens,
    parse_pathname_pattern_tokens,
    pathname_tokens_to_regex_source,
)


class PathnamePatternTests(unittest.TestCase):
    """
    Verify pathname pattern tokenization and regex compilation.
    """

    def test_parse_returns_text_and_parameter_tokens(self) -> None:
        """
        Parse literal and parameter segments into structured tokens.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens("/users/:id"),
            [TextToken("/users/"), ParamToken("id")],
        )

    def test_parse_supports_wildcards_and_optional_groups(self) -> None:
        """
        Parse wildcard tokens and nested optional groups.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens("/files{/*path}"),
            [TextToken("/files"), GroupToken([TextToken("/"), WildcardToken("path")])],
        )

    def test_parse_supports_quoted_parameter_names(self) -> None:
        """
        Parse quoted parameter names that include characters outside identifiers.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens('/users/:"user-id"'),
            [TextToken("/users/"), ParamToken("user-id")],
        )

    def test_parse_treats_escaped_special_characters_as_literal_text(self) -> None:
        """
        Keep escaped syntax characters in literal text tokens.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens(r"/literal\:value\{x\}"),
            [TextToken("/literal:value{x}")],
        )

    def test_parse_rejects_missing_parameter_name(self) -> None:
        """
        Reject parameter syntax that does not provide a name.
        """

        with self.assertRaisesRegex(ValueError, "missing parameter name"):
            _ = parse_pathname_pattern_tokens("/users/:/")

    def test_parse_rejects_unterminated_quote(self) -> None:
        """
        Reject quoted parameter names without a closing quote.
        """

        with self.assertRaisesRegex(ValueError, "unterminated quote"):
            _ = parse_pathname_pattern_tokens('/users/:"user-id')

    def test_parse_rejects_unexpected_special_character(self) -> None:
        """
        Reject unsupported pattern syntax characters.
        """

        with self.assertRaisesRegex(ValueError, r"unexpected \+"):
            _ = parse_pathname_pattern_tokens("/users/+")

    def test_flatten_expands_optional_group_including_omission(self) -> None:
        """
        Expand optional groups to both included and omitted sequences.
        """

        tokens = parse_pathname_pattern_tokens("/users{/me}")

        self.assertEqual(
            flatten_pathname_pattern_tokens(tokens),
            [
                [TextToken("/users"), TextToken("/me")],
                [TextToken("/users")],
            ],
        )

    def test_flatten_rejects_too_many_optional_combinations(self) -> None:
        """
        Reject patterns that expand into too many optional combinations.
        """

        pattern = "".join("{/a}" for _ in range(9))

        with self.assertRaisesRegex(ValueError, "too many path combinations"):
            _ = flatten_pathname_pattern_tokens(parse_pathname_pattern_tokens(pattern))

    def test_tokens_to_regex_source_escapes_literal_text(self) -> None:
        """
        Escape regex metacharacters in literal pathname text.
        """

        self.assertEqual(
            pathname_tokens_to_regex_source(
                [TextToken("/file.+"), ParamToken("name"), WildcardToken("rest")]
            ),
            r"/file\.\+([^/]+)(.+)",
        )

    def test_compile_matches_optional_group_and_optional_trailing_slash(self) -> None:
        """
        Match both optional-group variants and permit a trailing slash.
        """

        pattern = compile_pathname_pattern("/users{/me}")

        self.assertIsNotNone(pattern.fullmatch("/users"))
        self.assertIsNotNone(pattern.fullmatch("/users/"))
        self.assertIsNotNone(pattern.fullmatch("/users/me"))
        self.assertIsNotNone(pattern.fullmatch("/users/me/"))
        self.assertIsNone(pattern.fullmatch("/users/me/extra"))

    def test_compile_matches_path_without_variables(self) -> None:
        """
        Match an exact literal pathname pattern that does not define variables.
        """

        pattern = compile_pathname_pattern("/registry/v1/latest/registry+json")

        self.assertIsNotNone(pattern.fullmatch("/registry/v1/latest/registry+json"))
        self.assertIsNotNone(pattern.fullmatch("/registry/v1/latest/registry+json/"))
        self.assertIsNone(pattern.fullmatch("/registry/v1/latest/registry-json"))
        self.assertIsNone(pattern.fullmatch("/registry/v1/latest/registry+json/extra"))

    def test_compile_rejects_full_url_patterns(self) -> None:
        """
        Reject full URLs because pathname patterns match only URL paths.
        """

        with self.assertRaisesRegex(ValueError, "must be a URL path"):
            _ = compile_pathname_pattern(
                "https://github.com/moonrepo/moon/git-upload-pack"
            )

    def test_compile_requires_trailing_slash_when_pattern_ends_with_slash(self) -> None:
        """
        Preserve a required trailing slash when the pattern explicitly ends with one.
        """

        pattern = compile_pathname_pattern("/users/")

        self.assertIsNotNone(pattern.fullmatch("/users/"))
        self.assertIsNone(pattern.fullmatch("/users"))

    def test_compile_matches_params_but_not_empty_segments(self) -> None:
        """
        Match parameter segments only when they contain at least one character.
        """

        pattern = compile_pathname_pattern("/users/:id")

        self.assertIsNotNone(pattern.fullmatch("/users/123"))
        self.assertIsNone(pattern.fullmatch("/users/"))

    def test_compile_matches_wildcards_across_multiple_segments(self) -> None:
        """
        Match wildcard tokens across one or more path segments.
        """

        pattern = compile_pathname_pattern("/files/*path")

        self.assertIsNotNone(pattern.fullmatch("/files/a"))
        self.assertIsNotNone(pattern.fullmatch("/files/a/b/c"))
        self.assertIsNone(pattern.fullmatch("/files/"))


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
