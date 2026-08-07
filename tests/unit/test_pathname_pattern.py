"""
Unit tests for pathname pattern parsing and compilation.
"""

import unittest

from src.addon.pathname_pattern import (
    GroupToken,
    ParamToken,
    RegexToken,
    TextToken,
    WildcardToken,
    compile_pathname_pattern,
    flatten_pathname_pattern_tokens,
    parse_pathname_pattern_tokens,
    pathname_tokens_to_regex_source,
)


class PathnamePatternTests(unittest.TestCase):
    """
    Verify pathname pattern tokenization and URLPattern-style compilation.
    """

    def test_parse_returns_text_and_parameter_tokens(self) -> None:
        """
        Parse literal and parameter segments into structured tokens.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens("/users/:id"),
            [TextToken("/users/"), ParamToken("id")],
        )

    def test_parse_supports_wildcards_and_delimited_groups(self) -> None:
        """
        Parse unnamed wildcard tokens inside delimited groups.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens("/files{/*}"),
            [TextToken("/files"), GroupToken([TextToken("/"), WildcardToken()])],
        )

    def test_parse_treats_text_after_wildcard_as_literal(self) -> None:
        """
        Treat wildcard suffix text as fixed text instead of a wildcard name.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens("/files/*path"),
            [TextToken("/files/"), WildcardToken(), TextToken("path")],
        )

    def test_parse_supports_quoted_parameter_names(self) -> None:
        """
        Parse quoted parameter names that include characters outside identifiers.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens('/users/:"user-id"'),
            [TextToken("/users/"), ParamToken("user-id")],
        )

    def test_parse_supports_regex_groups_and_modifiers(self) -> None:
        """
        Parse custom parameter regexes, unnamed regexes, and group modifiers.
        """

        self.assertEqual(
            parse_pathname_pattern_tokens(r"/books/:id(\d+)?/(foo|bar)+"),
            [
                TextToken("/books/"),
                ParamToken("id", r"\d+", "?"),
                TextToken("/"),
                RegexToken("foo|bar", "+"),
            ],
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

    def test_parse_rejects_nested_delimited_groups(self) -> None:
        """
        Reject nested group delimiters as required by URLPattern syntax.
        """

        with self.assertRaisesRegex(ValueError, "nested group delimiter"):
            _ = parse_pathname_pattern_tokens("/users{{/me}?}")

    def test_flatten_expands_optional_group_including_omission(self) -> None:
        """
        Expand optional groups to both included and omitted sequences.
        """

        tokens = parse_pathname_pattern_tokens("/users{/me}?")

        self.assertEqual(
            flatten_pathname_pattern_tokens(tokens),
            [
                [TextToken("/users"), TextToken("/me")],
                [TextToken("/users")],
            ],
        )

    def test_flatten_keeps_unmodified_group_required(self) -> None:
        """
        Keep an unmodified delimited group in every flat sequence.
        """

        tokens = parse_pathname_pattern_tokens("/users{/me}")

        self.assertEqual(
            flatten_pathname_pattern_tokens(tokens),
            [[TextToken("/users"), TextToken("/me")]],
        )

    def test_flatten_rejects_too_many_optional_combinations(self) -> None:
        """
        Reject patterns that expand into too many optional combinations.
        """

        pattern = "".join("{/a}?" for _ in range(9))

        with self.assertRaisesRegex(ValueError, "too many path combinations"):
            _ = flatten_pathname_pattern_tokens(parse_pathname_pattern_tokens(pattern))

    def test_tokens_to_regex_source_escapes_literal_text(self) -> None:
        """
        Escape text while translating parameters and wildcards to regex.
        """

        self.assertEqual(
            pathname_tokens_to_regex_source(
                [TextToken("/file.+"), ParamToken("name"), WildcardToken()]
            ),
            r"/file\.\+(?:[^/]+?)(?:.*)",
        )

    def test_compile_requires_unmodified_delimited_group(self) -> None:
        """
        Require a delimited group when it has no optional modifier.
        """

        pattern = compile_pathname_pattern("/users{/me}")

        self.assertIsNotNone(pattern.fullmatch("/users/me"))
        self.assertIsNone(pattern.fullmatch("/users"))

    def test_compile_matches_optional_delimited_group(self) -> None:
        """
        Match both variants when a delimited group has an optional modifier.
        """

        pattern = compile_pathname_pattern("/users{/me}?")

        self.assertIsNotNone(pattern.fullmatch("/users"))
        self.assertIsNotNone(pattern.fullmatch("/users/me"))
        self.assertIsNone(pattern.fullmatch("/users/"))

    def test_compile_matches_path_without_variables_strictly(self) -> None:
        """
        Match a literal pathname without adding an optional trailing slash.
        """

        pattern = compile_pathname_pattern("/registry/v1/latest/registry+json")

        self.assertIsNotNone(pattern.fullmatch("/registry/v1/latest/registry+json"))
        self.assertIsNone(pattern.fullmatch("/registry/v1/latest/registry+json/"))
        self.assertIsNone(pattern.fullmatch("/registry/v1/latest/registry-json"))

    def test_compile_rejects_full_url_patterns(self) -> None:
        """
        Reject full URLs because pathname patterns match only URL paths.
        """

        with self.assertRaisesRegex(ValueError, "must be a URL path"):
            _ = compile_pathname_pattern(
                "https://github.com/moonrepo/moon/git-upload-pack"
            )

    def test_compile_requires_explicit_trailing_slash(self) -> None:
        """
        Match trailing slashes only when represented by the pattern.
        """

        without_slash = compile_pathname_pattern("/users")
        with_slash = compile_pathname_pattern("/users/")

        self.assertIsNotNone(without_slash.fullmatch("/users"))
        self.assertIsNone(without_slash.fullmatch("/users/"))
        self.assertIsNotNone(with_slash.fullmatch("/users/"))
        self.assertIsNone(with_slash.fullmatch("/users"))

    def test_compile_matches_params_but_not_empty_segments(self) -> None:
        """
        Match parameter segments only when they contain at least one character.
        """

        pattern = compile_pathname_pattern("/users/:id")

        self.assertIsNotNone(pattern.fullmatch("/users/123"))
        self.assertIsNone(pattern.fullmatch("/users/"))

    def test_compile_applies_automatic_prefix_to_optional_param(self) -> None:
        """
        Make the preceding slash optional with an optional pathname parameter.
        """

        pattern = compile_pathname_pattern("/books/:id?")

        self.assertIsNotNone(pattern.fullmatch("/books"))
        self.assertIsNotNone(pattern.fullmatch("/books/123"))
        self.assertIsNone(pattern.fullmatch("/books/"))

    def test_compile_repeats_parameter_with_automatic_prefix(self) -> None:
        """
        Repeat a parameter together with its pathname slash prefix.
        """

        one_or_more = compile_pathname_pattern("/books/:id+")
        zero_or_more = compile_pathname_pattern("/authors/:id*")

        self.assertIsNotNone(one_or_more.fullmatch("/books/123/456"))
        self.assertIsNone(one_or_more.fullmatch("/books"))
        self.assertIsNotNone(zero_or_more.fullmatch("/authors"))
        self.assertIsNotNone(zero_or_more.fullmatch("/authors/123/456"))
        self.assertIsNone(zero_or_more.fullmatch("/authors/"))

    def test_compile_matches_bare_wildcard_zero_or_more_times(self) -> None:
        """
        Match a JavaScript URLPattern wildcard across zero or more characters.
        """

        pattern = compile_pathname_pattern("/login/*")

        self.assertIsNone(pattern.fullmatch("/login"))
        self.assertIsNotNone(pattern.fullmatch("/login/"))
        self.assertIsNotNone(pattern.fullmatch("/login/callback"))
        self.assertIsNotNone(pattern.fullmatch("/login/oauth/callback"))

    def test_compile_treats_wildcard_suffix_as_literal(self) -> None:
        """
        Require fixed text written immediately after a bare wildcard.
        """

        pattern = compile_pathname_pattern("/files/*path")

        self.assertIsNotNone(pattern.fullmatch("/files/path"))
        self.assertIsNotNone(pattern.fullmatch("/files/nested/path"))
        self.assertIsNone(pattern.fullmatch("/files/file"))

    def test_compile_matches_custom_and_unnamed_regex_groups(self) -> None:
        """
        Apply custom regex matching to named and unnamed groups.
        """

        named = compile_pathname_pattern(r"/books/:id(\d+)")
        unnamed = compile_pathname_pattern("/(foo|bar)")

        self.assertIsNotNone(named.fullmatch("/books/123"))
        self.assertIsNone(named.fullmatch("/books/abc"))
        self.assertIsNotNone(unnamed.fullmatch("/foo"))
        self.assertIsNotNone(unnamed.fullmatch("/bar"))
        self.assertIsNone(unnamed.fullmatch("/baz"))

    def test_compile_can_make_trailing_slash_optional_explicitly(self) -> None:
        """
        Support URLPattern's explicit optional trailing slash idiom.
        """

        pattern = compile_pathname_pattern("/books{/}?")

        self.assertIsNotNone(pattern.fullmatch("/books"))
        self.assertIsNotNone(pattern.fullmatch("/books/"))


if __name__ == "__main__":
    _test_program = unittest.main(verbosity=2)
