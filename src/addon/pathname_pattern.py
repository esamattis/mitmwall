"""
URLPattern-style pathname parsing and compilation helpers.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class TextToken:
    """
    Literal text segment in a pathname pattern.
    """

    value: str


@dataclass(frozen=True)
class ParamToken:
    """
    Named pathname parameter with an optional regex and modifier.
    """

    name: str
    regex_source: str | None = None
    modifier: str = ""


@dataclass(frozen=True)
class WildcardToken:
    """
    Unnamed pathname wildcard with an optional modifier.
    """

    modifier: str = ""


@dataclass(frozen=True)
class RegexToken:
    """
    Unnamed regular-expression pathname group with an optional modifier.
    """

    source: str
    modifier: str = ""


@dataclass(frozen=True)
class GroupToken:
    """
    Delimited pathname pattern tokens with an optional modifier.
    """

    tokens: list["PathnamePatternToken"]
    modifier: str = ""


FlatPathnamePatternToken = TextToken | ParamToken | WildcardToken | RegexToken
PathnamePatternToken = FlatPathnamePatternToken | GroupToken


def is_parameter_name_start(char: str | None) -> bool:
    """
    Return whether a character can start a pathname parameter name.
    """

    return char is not None and (char == "$" or char == "_" or char.isalpha())


def is_parameter_name_continue(char: str | None) -> bool:
    """
    Return whether a character can continue a pathname parameter name.
    """

    return char is not None and (
        char == "$"
        or char == "_"
        or char == "\u200c"
        or char == "\u200d"
        or char.isalpha()
        or char.isdigit()
    )


def parse_pathname_pattern_tokens(pattern: str) -> list[PathnamePatternToken]:
    """
    Parse supported URLPattern pathname syntax into structured tokens.
    """

    chars = list(pattern)
    index = 0

    def current_char() -> str | None:
        """
        Return the current pattern character without advancing.
        """

        if index >= len(chars):
            return None
        return chars[index]

    def consume_modifier() -> str:
        """
        Consume and return a URLPattern group modifier when present.
        """

        nonlocal index
        value = current_char()
        if value not in {"?", "+", "*"}:
            return ""
        index += 1
        return value

    def consume_name() -> str:
        """
        Consume a named-group identifier or quoted name.
        """

        nonlocal index
        name = ""
        if is_parameter_name_start(current_char()):
            while is_parameter_name_continue(current_char()):
                name += chars[index]
                index += 1
            return name

        if current_char() != '"':
            return name

        quote_start = index
        index += 1
        while index < len(chars):
            quoted = chars[index]
            index += 1
            if quoted == '"':
                return name
            if quoted == "\\":
                if index == len(chars):
                    raise ValueError(f"unexpected end after \\ at index {index}")
                quoted = chars[index]
                index += 1
            name += quoted
        raise ValueError(f"unterminated quote at index {quote_start}")

    def consume_regex() -> str:
        """
        Consume a balanced parenthesized regular-expression group.
        """

        nonlocal index
        start = index
        index += 1
        depth = 1
        in_character_class = False
        source = ""

        while index < len(chars):
            value = chars[index]
            index += 1

            if value == "\\":
                if index == len(chars):
                    raise ValueError(f"unexpected end after \\ at index {index}")
                source += value + chars[index]
                index += 1
                continue

            if value == "[":
                in_character_class = True
            elif value == "]" and in_character_class:
                in_character_class = False
            elif not in_character_class and value == "(":
                depth += 1
            elif not in_character_class and value == ")":
                depth -= 1
                if depth == 0:
                    return source

            source += value

        raise ValueError(f"unterminated regex group at index {start}")

    def consume_until(end: str) -> list[PathnamePatternToken]:
        """
        Consume tokens until the requested group terminator is reached.
        """

        nonlocal index
        output: list[PathnamePatternToken] = []
        path = ""

        def write_path() -> None:
            """
            Flush accumulated literal pathname text into the token stream.
            """

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

            if value == ":":
                name = consume_name()
                if not name:
                    raise ValueError(f"missing parameter name at index {index}")
                regex_source = consume_regex() if current_char() == "(" else None
                modifier = consume_modifier()
                write_path()
                output.append(ParamToken(name, regex_source, modifier))
                continue

            if value == "*":
                modifier = consume_modifier()
                write_path()
                output.append(WildcardToken(modifier))
                continue

            if value == "(":
                index -= 1
                regex_source = consume_regex()
                modifier = consume_modifier()
                write_path()
                output.append(RegexToken(regex_source, modifier))
                continue

            if value == "{":
                if end:
                    raise ValueError(f"nested group delimiter at index {index - 1}")
                write_path()
                tokens = consume_until("}")
                output.append(GroupToken(tokens, consume_modifier()))
                continue

            if value in "}[]+?":
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
    """
    Expand optional delimited groups into flat pathname token sequences.

    This compatibility helper cannot flatten repeating delimited groups.
    """

    sequences: list[list[FlatPathnamePatternToken]] = [[]]

    for token in tokens:
        if not isinstance(token, GroupToken):
            for sequence in sequences:
                sequence.append(token)
            continue

        if token.modifier in {"+", "*"}:
            raise ValueError("repeating groups cannot be flattened")

        group_sequences = flatten_pathname_pattern_tokens(token.tokens)
        included = [
            sequence + group_sequence
            for sequence in sequences
            for group_sequence in group_sequences
        ]
        sequences = included + sequences if token.modifier == "?" else included
        if len(sequences) > 256:
            raise ValueError("too many path combinations")

    return sequences


def _modified_regex_source(body: str, modifier: str, prefix: str = "") -> str:
    """
    Wrap regex source with its URLPattern modifier and pathname prefix.
    """

    combined = f"{re.escape(prefix)}(?:{body})"
    if not modifier:
        return combined
    return f"(?:{combined}){modifier}"


def _tokens_to_regex_source(
    tokens: Sequence[PathnamePatternToken], *, automatic_prefix: bool
) -> str:
    """
    Convert pathname tokens to regex source with URLPattern slash prefixing.
    """

    source = ""
    previous_token: PathnamePatternToken | None = None

    for token in tokens:
        if isinstance(token, TextToken):
            source += re.escape(token.value)
            previous_token = token
            continue

        if isinstance(token, GroupToken):
            body = _tokens_to_regex_source(token.tokens, automatic_prefix=False)
            source += _modified_regex_source(body, token.modifier)
            previous_token = token
            continue

        prefix = ""
        modifier = token.modifier
        if (
            automatic_prefix
            and modifier
            and isinstance(previous_token, TextToken)
            and previous_token.value.endswith("/")
        ):
            source = source[:-1]
            prefix = "/"

        if isinstance(token, ParamToken):
            body = token.regex_source or "[^/]+?"
        elif isinstance(token, WildcardToken):
            body = ".*"
        else:
            body = token.source

        source += _modified_regex_source(body, modifier, prefix)
        previous_token = token

    return source


def pathname_tokens_to_regex_source(
    tokens: Sequence[FlatPathnamePatternToken],
) -> str:
    """
    Convert a flat pathname token sequence into regex source text.
    """

    return _tokens_to_regex_source(tokens, automatic_prefix=True)


def is_literal_pathname_pattern(pattern: str) -> bool:
    """
    Return whether a pathname pattern contains no pattern syntax tokens.
    """

    return not any(char in pattern for char in ":*{}()\\")


def is_full_url_pathname_pattern(pattern: str) -> bool:
    """
    Return whether a pathname pattern appears to contain a full URL.
    """

    parsed = urlsplit(pattern)
    return bool(parsed.scheme and parsed.netloc)


def compile_pathname_pattern(pattern: str) -> re.Pattern[str]:
    """
    Compile supported URLPattern pathname syntax to a case-sensitive regex.
    """

    if is_full_url_pathname_pattern(pattern):
        raise ValueError("pathname_pattern must be a URL path, not a full URL")

    if is_literal_pathname_pattern(pattern):
        source = re.escape(pattern)
    else:
        tokens = parse_pathname_pattern_tokens(pattern)
        source = _tokens_to_regex_source(tokens, automatic_prefix=True)

    try:
        return re.compile(f"(?:{source})")
    except re.error as exc:
        raise ValueError(f"invalid pathname_pattern regex: {exc}") from exc
