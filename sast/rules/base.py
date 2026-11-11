"""规则基类与 Finding 数据结构。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    message: str
    file: str
    line: int
    severity: str = "warning"
    snippet: str = ""

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "snippet": self.snippet,
        }


class Rule:
    """所有 AST 规则的基类。子类实现 check(node, context) 并返回 Finding 列表。"""

    rule_id: str = "BASE"
    description: str = ""
    severity: str = "warning"

    def check(self, node, context):
        raise NotImplementedError
