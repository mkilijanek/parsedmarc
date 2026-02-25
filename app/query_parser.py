from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Union, Tuple
import re

# Kibana-ish tokens
# Supports: field:value, comparisons > < >= <=, wildcards * ?, AND/OR/NOT, parentheses, quoted strings

TOKEN_RE = re.compile(
    r"""\s*(?:
    (?P<LPAREN>\()|
    (?P<RPAREN>\))|
    (?P<OPERATOR>\bAND\b|\bOR\b|\bNOT\b)|
    (?P<COMP>>=|<=|>|<|:)|
    (?P<QUOTED>\"([^\\"\\]|\\.)*\")|
    (?P<WORD>[A-Za-z0-9_\.\-\*\?]+)
    )\s*""",
    re.IGNORECASE | re.VERBOSE,
)

@dataclass(frozen=True)
class Term:
    field: str
    op: str   # ':', '>', '<', '>=', '<='
    value: str

Token = Union[str, Term]  # str: 'AND'/'OR'/'NOT'/'(' / ')'

def tokenize(query: str) -> List[Token]:
    tokens: List[Token] = []
    pos = 0
    while pos < len(query):
        m = TOKEN_RE.match(query, pos)
        if not m:
            raise ValueError(f"Invalid token near: {query[pos:pos+20]!r}")
        pos = m.end()
        gd = m.groupdict()
        if gd["LPAREN"]:
            tokens.append("(")
        elif gd["RPAREN"]:
            tokens.append(")")
        elif gd["OPERATOR"]:
            tokens.append(gd["OPERATOR"].upper())
        elif gd["QUOTED"]:
            # Quoted values are treated as WORD; colon/comparison handled in parser
            tokens.append(gd["QUOTED"][1:-1].encode('utf-8').decode('unicode_escape'))
        elif gd["WORD"]:
            tokens.append(gd["WORD"])
        elif gd["COMP"]:
            tokens.append(gd["COMP"])
        else:
            raise ValueError("Unreachable")
    return tokens

def _is_operator(tok: Token) -> bool:
    return isinstance(tok, str) and tok in {"AND","OR","NOT"}

def _precedence(op: str) -> int:
    return {"NOT":3, "AND":2, "OR":1}.get(op, 0)

def parse_kibana_query(query: str) -> List[Token]:
    """Parse into Reverse Polish Notation (RPN) tokens for boolean evaluation.

    Grammar (simplified):
      expr := term ( (AND|OR) term )*
      term := NOT? ( predicate | '(' expr ')' )
      predicate := field (':' | '>' | '<' | '>=' | '<=') value

    Returns RPN list mixing Term and operator strings.
    """
    raw = tokenize(query)
    # First, turn sequences into predicates (Term)
    i = 0
    parsed: List[Token] = []
    while i < len(raw):
        tok = raw[i]
        if isinstance(tok, str) and tok in {"(",")","AND","OR","NOT"}:
            parsed.append(tok.upper() if tok not in {"(",")"} else tok)
            i += 1
            continue
        # Expect predicate: <field> <comp> <value>
        if not isinstance(tok, str):
            raise ValueError("Unexpected token")
        field = tok
        if i+2 >= len(raw):
            raise ValueError("Incomplete predicate")
        comp = raw[i+1]
        val = raw[i+2]
        if not (isinstance(comp, str) and comp in {":",">","<",">=","<="}):
            raise ValueError("Expected comparison operator after field")
        # Support Kibana-style numeric comparisons written as field:>70
        # by normalizing ":" + ">" + "70" to ">" + "70".
        if comp == ":" and isinstance(val, str) and val in {">","<",">=","<="}:
            if i + 3 >= len(raw):
                raise ValueError("Expected value after comparison operator")
            comp = val
            val = raw[i+3]
            i += 1
        if not isinstance(val, str):
            raise ValueError("Expected value")
        parsed.append(Term(field=field, op=comp, value=val))
        i += 3

    # Shunting-yard to RPN
    output: List[Token] = []
    stack: List[str] = []
    for tok in parsed:
        if isinstance(tok, Term):
            output.append(tok)
        elif tok == "(":
            stack.append(tok)
        elif tok == ")":
            while stack and stack[-1] != "(":
                output.append(stack.pop())
            if not stack or stack[-1] != "(":
                raise ValueError("Mismatched parentheses")
            stack.pop()
        elif _is_operator(tok):
            op = tok
            while stack and _is_operator(stack[-1]) and _precedence(stack[-1]) >= _precedence(op):
                output.append(stack.pop())
            stack.append(op)
        else:
            raise ValueError(f"Unknown token: {tok}")
    while stack:
        if stack[-1] in {"(",")"}:
            raise ValueError("Mismatched parentheses")
        output.append(stack.pop())
    return output
