"""
URLPattern-style pathname parsing and compilation helpers.
"""

import re
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
    Named pathname segment parameter token.
    """

    name: str


@dataclass(frozen=True)
class WildcardToken:
    """
    Named pathname wildcard token that can span multiple characters.
    """

    name: str


@dataclass(frozen=True)
class GroupToken:
    """
    Optional group of pathname pattern tokens.
    """

    tokens: list["PathnamePatternToken"]


FlatPathnamePatternToken = TextToken | ParamToken | WildcardToken
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
    Parse a URLPattern-style pathname pattern into structured tokens.
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

    def consume_until(end: str) -> list[PathnamePatternToken]:
        """
        Consume tokens until the requested terminator is reached.
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
    """
    Expand optional groups into all flat pathname token sequences.
    """

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
    """
    Convert a flat pathname token sequence into regex source text.
    """

    source = ""
    for token in tokens:
        if isinstance(token, TextToken):
            source += re.escape(token.value)
        elif isinstance(token, ParamToken):
            source += "([^/]+)"
        else:
            source += "(.+)"
    return source


def is_literal_pathname_pattern(pattern: str) -> bool:
    """
    Return whether a pathname pattern contains no pattern syntax tokens.
    """

    return not any(char in pattern for char in ":*{}\\")


def is_full_url_pathname_pattern(pattern: str) -> bool:
    """
    Return whether a pathname pattern appears to contain a full URL.
    """

    parsed = urlsplit(pattern)
    return bool(parsed.scheme and parsed.netloc)


def compile_pathname_pattern(pattern: str) -> re.Pattern[str]:
    """
    Compile a URLPattern-style pathname pattern to a case-sensitive regex.
    """

    if is_full_url_pathname_pattern(pattern):
        raise ValueError("pathname_pattern must be a URL path, not a full URL")

    if is_literal_pathname_pattern(pattern):
        source = re.escape(pattern)
    else:
        tokens = parse_pathname_pattern_tokens(pattern)
        sequences = flatten_pathname_pattern_tokens(tokens)
        source = "|".join(
            pathname_tokens_to_regex_source(sequence) for sequence in sequences
        )
    trailing = "" if pattern.endswith("/") else "/?"
    return re.compile(f"(?:{source}){trailing}")
