"""Pure-stdlib parsers, serializers, and key-path utilities (JSON, JSONC, TOML, YAML)."""

from __future__ import annotations

import copy
import json
import re
import tomllib
from typing import Any


class FormatError(ValueError):
    """Raised when JSON, JSONC, TOML, YAML, or Markdown frontmatter fails to parse."""


_MISSING = object()
_BARE_TOML_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def strip_jsonc(text: str) -> str:
    """Remove // comments, /* */ comments, and trailing commas outside JSON string literals."""
    if text.startswith("\ufeff"):
        raise FormatError("UTF-8 BOM is forbidden in JSON/JSONC files")

    out: list[str] = []
    n = len(text)
    i = 0
    in_str = False
    escape = False

    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            i += 1
            continue

        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            closed = False
            while i + 1 < n:
                if text[i] == "*" and text[i + 1] == "/":
                    i += 2
                    closed = True
                    break
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            if not closed:
                raise FormatError("Unterminated /* */ comment in JSONC")
        else:
            out.append(ch)
            i += 1

    no_comments = "".join(out)

    # Remove trailing commas before } or ] outside strings.
    cleaned: list[str] = []
    in_str = False
    escape = False
    m = len(no_comments)
    j = 0
    while j < m:
        ch = no_comments[j]
        if in_str:
            cleaned.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            j += 1
            continue
        if ch == '"':
            in_str = True
            cleaned.append(ch)
            j += 1
            continue
        if ch == ",":
            k = j + 1
            while k < m and no_comments[k] in " \t\r\n":
                k += 1
            if k < m and no_comments[k] in ("}", "]"):
                j += 1
                continue
        cleaned.append(ch)
        j += 1

    return "".join(cleaned)


def parse_json(text: str) -> Any:
    """Strictly parse JSON (rejecting UTF-8 BOM and comments)."""
    if text.startswith("\ufeff"):
        raise FormatError("UTF-8 BOM is forbidden in JSON files")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise FormatError(f"Invalid JSON: {exc}") from exc


def parse_jsonc(text: str) -> Any:
    """Parse JSON with comments and trailing commas."""
    stripped = strip_jsonc(text)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise FormatError(f"Invalid JSONC: {exc}") from exc


def dump_json(data: Any, sort_keys: bool = False) -> str:
    """Deterministically serialize JSON with trailing newline."""
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=sort_keys) + "\n"


def parse_toml(text: str) -> dict[str, Any]:
    """Parse TOML using Python 3.12 stdlib tomllib."""
    if text.startswith("\ufeff"):
        raise FormatError("UTF-8 BOM is forbidden in TOML files")
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise FormatError(f"Invalid TOML: {exc}") from exc


def _toml_key(key: str) -> str:
    if _BARE_TOML_KEY_RE.match(key):
        return key
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_scalar(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, str):
        escaped = (
            val.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\b", "\\b")
            .replace("\t", "\\t")
            .replace("\n", "\\n")
            .replace("\f", "\\f")
            .replace("\r", "\\r")
        )
        return f'"{escaped}"'
    if isinstance(val, list):
        items = [_toml_scalar(v) for v in val if v is not None]
        return "[" + ", ".join(items) + "]"
    if isinstance(val, dict):
        pairs = [f"{_toml_key(str(k))} = {_toml_scalar(v)}" for k, v in val.items() if v is not None]
        return "{ " + ", ".join(pairs) + " }"
    raise FormatError(f"Unsupported TOML value type: {type(val).__name__}")


def _emit_toml_table(lines: list[str], data: dict[str, Any], prefix: list[str]) -> None:
    scalars: list[tuple[str, Any]] = []
    subtables: list[tuple[str, dict[str, Any]]] = []
    array_tables: list[tuple[str, list[dict[str, Any]]]] = []

    for key, val in data.items():
        if val is None:
            continue
        if isinstance(val, dict):
            subtables.append((str(key), val))
        elif isinstance(val, list) and val and all(isinstance(item, dict) for item in val):
            array_tables.append((str(key), val))
        else:
            scalars.append((str(key), val))

    for key, val in scalars:
        lines.append(f"{_toml_key(key)} = {_toml_scalar(val)}")

    for key, sub in subtables:
        path = prefix + [key]
        header = ".".join(_toml_key(p) for p in path)
        if lines and lines[-1] != "":
            lines.append("")
        lines.append(f"[{header}]")
        _emit_toml_table(lines, sub, path)

    for key, items in array_tables:
        path = prefix + [key]
        header = ".".join(_toml_key(p) for p in path)
        for item in items:
            if lines and lines[-1] != "":
                lines.append("")
            lines.append(f"[[{header}]]")
            _emit_toml_table(lines, item, path)


def dump_toml(data: dict[str, Any]) -> str:
    """Deterministically serialize a dict to valid TOML."""
    lines: list[str] = []
    _emit_toml_table(lines, data, [])
    return ("\n".join(lines).rstrip() + "\n") if lines else ""


def _split_yaml_inline_items(inner: str) -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    in_sq = False
    in_dq = False
    escape = False
    depth = 0
    for ch in inner:
        if in_dq:
            buf.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_dq = False
            continue
        if in_sq:
            buf.append(ch)
            if ch == "'":
                in_sq = False
            continue
        if ch == '"':
            in_dq = True
            buf.append(ch)
        elif ch == "'":
            in_sq = True
            buf.append(ch)
        elif ch in "[{":
            depth += 1
            buf.append(ch)
        elif ch in "]}":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            item = "".join(buf).strip()
            if item:
                items.append(item)
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _strip_yaml_comment(line: str) -> str:
    in_sq = False
    in_dq = False
    escape = False
    for idx, ch in enumerate(line):
        if in_dq:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_dq = False
            continue
        if in_sq:
            if ch == "'":
                in_sq = False
            continue
        if ch == '"':
            in_dq = True
        elif ch == "'":
            in_sq = True
        elif ch == "#" and (idx == 0 or line[idx - 1].isspace()):
            return line[:idx].rstrip()
    return line.rstrip()


def _parse_yaml_scalar(token: str) -> Any:
    s = token.strip()
    if s == "" or s in ("null", "Null", "NULL", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s[1:-1]
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar(item) for item in _split_yaml_inline_items(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        if not inner:
            return {}
        mapping: dict[str, Any] = {}
        for part in _split_yaml_inline_items(inner):
            k, v = _split_yaml_kv(part)
            mapping[str(_parse_yaml_scalar(k) if k[0] in "\"'" else k)] = _parse_yaml_scalar(v)
        return mapping
    if re.fullmatch(r"-?[0-9]+", s):
        return int(s)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", s):
        return float(s)
    return s


def _split_yaml_kv(text: str) -> tuple[str, str]:
    in_sq = False
    in_dq = False
    escape = False
    for idx, ch in enumerate(text):
        if in_dq:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_dq = False
            continue
        if in_sq:
            if ch == "'":
                in_sq = False
            continue
        if ch == '"':
            in_dq = True
        elif ch == "'":
            in_sq = True
        elif ch == ":" and (idx + 1 == len(text) or text[idx + 1].isspace()):
            return text[:idx].strip(), text[idx + 1 :].strip()
    raise FormatError(f"Invalid YAML mapping line: {text!r}")


def _prep_yaml_lines(text: str) -> list[tuple[int, str]]:
    if text.startswith("\ufeff"):
        raise FormatError("UTF-8 BOM is forbidden in YAML files")
    prepared: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip(" \t"))]:
            raise FormatError("Tabs are not allowed in YAML indentation")
        stripped = _strip_yaml_comment(raw_line)
        if not stripped.strip():
            continue
        if stripped.strip() in ("---", "..."):
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        prepared.append((indent, stripped.lstrip(" ")))
    return prepared


def _parse_yaml_block(lines: list[tuple[int, str]], idx: int, base_indent: int) -> tuple[Any, int]:
    if idx >= len(lines):
        return {}, idx

    _, first_content = lines[idx]
    if first_content == "-" or first_content.startswith("- "):
        seq: list[Any] = []
        while idx < len(lines):
            indent, content = lines[idx]
            if indent < base_indent:
                break
            if indent > base_indent:
                raise FormatError(f"Unexpected YAML indentation at {content!r}")
            if not (content == "-" or content.startswith("- ")):
                break
            rest = content[1:].strip() if len(content) > 1 else ""
            if not rest:
                idx += 1
                if idx < len(lines) and lines[idx][0] > indent:
                    val, idx = _parse_yaml_block(lines, idx, lines[idx][0])
                    seq.append(val)
                else:
                    seq.append(None)
                continue
            # Check for "- key: val" list-of-mappings form.
            if ":" in rest and not rest.startswith(('"', "'", "[", "{")):
                try:
                    k, v = _split_yaml_kv(rest)
                    item_dict: dict[str, Any] = {}
                    item_indent = indent + 2
                    if _YAML_BLOCK_HEADER_RE.match(v):
                        block_val, idx = _consume_multiline_yaml(lines, idx + 1, indent + 1, v)
                        item_dict[_unquote_yaml_key(k)] = block_val
                    elif v == "":
                        idx += 1
                        if idx < len(lines) and lines[idx][0] > indent:
                            child, idx = _parse_yaml_block(lines, idx, lines[idx][0])
                            item_dict[_unquote_yaml_key(k)] = child
                        else:
                            item_dict[_unquote_yaml_key(k)] = None
                    else:
                        item_dict[_unquote_yaml_key(k)] = _parse_yaml_scalar(v)
                        idx += 1
                    if idx < len(lines) and lines[idx][0] >= item_indent and not lines[idx][1].startswith("- "):
                        more, idx = _parse_yaml_mapping(lines, idx, lines[idx][0])
                        item_dict.update(more)
                    seq.append(item_dict)
                    continue
                except FormatError:
                    pass
            seq.append(_parse_yaml_scalar(rest))
            idx += 1
        return seq, idx

    return _parse_yaml_mapping(lines, idx, base_indent)


def _unquote_yaml_key(k: str) -> str:
    if (k.startswith('"') and k.endswith('"')) or (k.startswith("'") and k.endswith("'")):
        return str(_parse_yaml_scalar(k))
    return k


_YAML_BLOCK_HEADER_RE = re.compile(r"^[|>][0-9]*[+-]?$|^[|>][+-][0-9]*$")


def _consume_multiline_yaml(
    lines: list[tuple[int, str]], idx: int, min_indent: int, header: str
) -> tuple[str, int]:
    folded = header.startswith(">")
    chunks: list[str] = []
    block_indent: int | None = None
    while idx < len(lines):
        indent, content = lines[idx]
        if indent < min_indent:
            break
        if block_indent is None:
            block_indent = indent
        pad = " " * max(0, indent - block_indent)
        chunks.append(pad + content)
        idx += 1
    joiner = " " if folded else "\n"
    text = joiner.join(chunks)
    if header.endswith("+"):
        text += "\n"
    return text, idx


def _parse_yaml_mapping(lines: list[tuple[int, str]], idx: int, base_indent: int) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while idx < len(lines):
        indent, content = lines[idx]
        if indent < base_indent:
            break
        if indent > base_indent:
            raise FormatError(f"Unexpected YAML indentation at {content!r}")
        if content == "-" or content.startswith("- "):
            break
        key_raw, val_raw = _split_yaml_kv(content)
        key = _unquote_yaml_key(key_raw)
        if _YAML_BLOCK_HEADER_RE.match(val_raw):
            block_val, idx = _consume_multiline_yaml(lines, idx + 1, base_indent + 1, val_raw)
            mapping[key] = block_val
        elif val_raw == "":
            idx += 1
            if idx < len(lines) and lines[idx][0] > base_indent:
                child, idx = _parse_yaml_block(lines, idx, lines[idx][0])
                mapping[key] = child
            elif idx < len(lines) and lines[idx][0] == base_indent and (
                lines[idx][1] == "-" or lines[idx][1].startswith("- ")
            ):
                child, idx = _parse_yaml_block(lines, idx, base_indent)
                mapping[key] = child
            else:
                mapping[key] = None
        else:
            mapping[key] = _parse_yaml_scalar(val_raw)
            idx += 1
    return mapping, idx


def parse_yaml_subset(text: str) -> Any:
    """Parse a clean YAML subset without third-party dependencies."""
    lines = _prep_yaml_lines(text)
    if not lines:
        return {}
    result, next_idx = _parse_yaml_block(lines, 0, lines[0][0])
    if next_idx < len(lines):
        raise FormatError(f"Unparsed trailing YAML content at {lines[next_idx][1]!r}")
    return result


def parse_yaml_frontmatter(text: str) -> tuple[dict[str, Any] | None, str]:
    """Extract and parse leading YAML frontmatter from Markdown."""
    if text.startswith("\ufeff"):
        raise FormatError("UTF-8 BOM is forbidden in Markdown files")
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        return None, text
    end_idx: int | None = None
    for idx in range(1, len(lines)):
        if lines[idx].rstrip("\r\n") in ("---", "..."):
            end_idx = idx
            break
    if end_idx is None:
        raise FormatError("Unterminated YAML frontmatter block (missing closing '---')")
    fm_text = "".join(lines[1:end_idx])
    parsed = parse_yaml_subset(fm_text)
    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        raise FormatError("YAML frontmatter root must be a mapping")
    body = "".join(lines[end_idx + 1 :])
    return parsed, body


def _yaml_scalar(val: Any) -> str:
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val)
    if s == "" or any(c in s for c in ":#{}[],&*?|-><!%@`'\"\n") or s.strip() != s or s in ("true", "false", "null"):
        return json.dumps(s, ensure_ascii=False)
    return s


def _emit_yaml(val: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines: list[str] = []
    if isinstance(val, dict):
        if not val:
            lines.append(f"{pad}{{}}")
            return lines
        for k, v in val.items():
            key_s = _yaml_scalar(str(k))
            if isinstance(v, dict):
                if not v:
                    lines.append(f"{pad}{key_s}: {{}}")
                else:
                    lines.append(f"{pad}{key_s}:")
                    lines.extend(_emit_yaml(v, indent + 2))
            elif isinstance(v, list):
                if not v:
                    lines.append(f"{pad}{key_s}: []")
                else:
                    lines.append(f"{pad}{key_s}:")
                    lines.extend(_emit_yaml(v, indent + 2))
            else:
                lines.append(f"{pad}{key_s}: {_yaml_scalar(v)}")
        return lines
    if isinstance(val, list):
        if not val:
            lines.append(f"{pad}[]")
            return lines
        for item in val:
            if isinstance(item, dict) and item:
                sub = _emit_yaml(item, indent + 2)
                first = sub[0].lstrip(" ")
                lines.append(f"{pad}- {first}")
                lines.extend(sub[1:])
            elif isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}-")
                lines.extend(_emit_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
        return lines
    lines.append(f"{pad}{_yaml_scalar(val)}")
    return lines


def dump_yaml(data: Any) -> str:
    """Deterministically serialize data to YAML."""
    if isinstance(data, dict) and not data:
        return "{}\n"
    return "\n".join(_emit_yaml(data)) + "\n"


def parse_env(text: str) -> dict[str, str]:
    """Parse a dotenv / KEY=VALUE file into a dict."""
    if text.startswith("\ufeff"):
        raise FormatError("UTF-8 BOM is forbidden in .env files")
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise FormatError(f"Invalid .env line (missing '='): {raw_line!r}")
        key, val = line.split("=", 1)
        key = key.strip()
        if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise FormatError(f"Invalid .env variable name: {key!r}")
        val = val.strip()
        if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
            val = val[1:-1]
        out[key] = val
    return out


def dump_env(data: dict[str, Any]) -> str:
    """Deterministically serialize a dict to KEY=VALUE format."""
    lines = ["# agentconfig hardened loopback-only Ollama environment"]
    for key, val in data.items():
        if val is None:
            continue
        lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"


def parse_by_format(text: str, fmt: str) -> Any:
    """Dispatch parser based on format name."""
    norm = fmt.lower()
    if norm == "json":
        return parse_json(text)
    if norm == "jsonc":
        return parse_jsonc(text)
    if norm == "toml":
        return parse_toml(text)
    if norm in ("yaml", "yml"):
        return parse_yaml_subset(text)
    if norm == "env":
        return parse_env(text)
    if norm in ("markdown", "md", "mdc"):
        fm, _ = parse_yaml_frontmatter(text)
        return fm or {}
    raise FormatError(f"Unsupported format: {fmt}")


def dump_by_format(data: Any, fmt: str) -> str:
    """Dispatch deterministic serializer based on format name."""
    norm = fmt.lower()
    if norm in ("json", "jsonc"):
        return dump_json(data)
    if norm == "toml":
        if not isinstance(data, dict):
            raise FormatError("TOML root must be a dict")
        return dump_toml(data)
    if norm in ("yaml", "yml"):
        return dump_yaml(data)
    if norm == "env":
        if not isinstance(data, dict):
            raise FormatError("ENV root must be a dict")
        return dump_env(data)
    raise FormatError(f"Unsupported serialization format: {fmt}")


def extract_key_paths(obj: Any, prefix: str = "") -> list[str]:
    """Return sorted unique dotted key paths for key-shape drift detection."""
    paths: set[str] = set()

    def walk(node: Any, cur: str) -> None:
        if isinstance(node, dict):
            if not node and cur:
                paths.add(cur)
                return
            for k, v in node.items():
                nxt = f"{cur}.{k}" if cur else str(k)
                paths.add(nxt)
                walk(v, nxt)
        elif isinstance(node, list):
            if cur:
                paths.add(f"{cur}[]")
            for item in node:
                if isinstance(item, (dict, list)):
                    walk(item, f"{cur}[]" if cur else "[]")

    walk(obj, prefix)
    return sorted(paths)


def get_dotted(obj: dict[str, Any], dotted_key: str, default: Any = _MISSING) -> Any:
    """Fetch a nested dict value using dot-separated key path."""
    cur: Any = obj
    for part in dotted_key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def set_dotted(obj: dict[str, Any], dotted_key: str, value: Any) -> None:
    """Set a nested dict value using dot-separated key path, creating parent dicts."""
    parts = dotted_key.split(".")
    cur = obj
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = copy.deepcopy(value)


def del_dotted(obj: dict[str, Any], dotted_key: str) -> bool:
    """Delete a nested dict key if present; returns True if deleted."""
    parts = dotted_key.split(".")
    cur: Any = obj
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    if isinstance(cur, dict) and parts[-1] in cur:
        del cur[parts[-1]]
        return True
    return False


def extract_managed_subtree(obj: dict[str, Any], managed_keys: list[str]) -> dict[str, Any]:
    """Build deterministic subtree containing only managed keys."""
    subtree: dict[str, Any] = {}
    for key in sorted(set(managed_keys)):
        val = get_dotted(obj, key, _MISSING)
        if val is not _MISSING:
            set_dotted(subtree, key, val)
    return subtree


def apply_managed_patch(
    existing: dict[str, Any],
    desired: dict[str, Any],
    managed_keys: list[str],
    removed_keys: list[str] | None = None,
) -> dict[str, Any]:
    """Patch only managed_keys into a copy of existing while deleting removed_keys."""
    patched = copy.deepcopy(existing)
    for rkey in removed_keys or []:
        del_dotted(patched, rkey)
    for mkey in managed_keys:
        val = get_dotted(desired, mkey, _MISSING)
        if val is not _MISSING:
            set_dotted(patched, mkey, val)
    return patched
