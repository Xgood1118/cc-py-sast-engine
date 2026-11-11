"""示例规则：检测硬编码密钥赋值（仅字面量，不做污点分析）。"""
import ast

from .base import Finding, Rule

SECRET_NAME_HINTS = ("password", "passwd", "secret", "token", "api_key", "apikey")


class HardcodedSecretRule(Rule):
    rule_id = "PY001"
    description = "硬编码密钥"
    severity = "error"

    def check(self, node, context):
        findings = []
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = target.id if isinstance(target, ast.Name) else ""
                if (
                    name.lower() in SECRET_NAME_HINTS
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            message=f"变量 {name} 被赋值为硬编码字符串字面量",
                            file=context["file"],
                            line=node.lineno,
                            severity=self.severity,
                            snippet=ast.get_source_segment(context["source"], node) or "",
                        )
                    )
        return findings
