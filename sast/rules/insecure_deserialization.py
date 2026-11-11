"""规则：检测不安全的反序列化调用（pickle / marshal）。"""
import ast

from .base import Finding, Rule

# 模块名 -> 被视为不安全的反序列化函数名集合
UNSAFE_FUNCS = {
    "pickle": {"load", "loads"},
    "marshal": {"loads"},
}


class InsecureDeserializationRule(Rule):
    rule_id = "PY002"
    description = "不安全反序列化"
    severity = "error"

    def check(self, node, context):
        findings = []
        if not isinstance(node, ast.Call):
            return findings
        func = node.func
        if not isinstance(func, ast.Attribute):
            return findings
        if not isinstance(func.value, ast.Name):
            return findings

        module = func.value.id
        attr = func.attr
        if attr not in UNSAFE_FUNCS.get(module, set()):
            return findings

        findings.append(
            Finding(
                rule_id=self.rule_id,
                message=(
                    f"检测到不安全的反序列化函数 {module}.{attr}() 调用，"
                    "反序列化不可信数据可能导致任意代码执行"
                ),
                file=context["file"],
                line=node.lineno,
                severity=self.severity,
                snippet=ast.get_source_segment(context["source"], node) or "",
            )
        )
        return findings
