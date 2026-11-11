"""AST 分析入口骨架。当前仅注册并遍历规则，不做跨函数污点传播。"""
import ast

from .rules.hardcoded_secret import HardcodedSecretRule
from .rules.insecure_deserialization import InsecureDeserializationRule


def load_rules():
    # TODO: 命令注入、路径穿越、SSRF 等规则尚未实现
    return [HardcodedSecretRule(), InsecureDeserializationRule()]


def analyze_source(source: str, filename: str):
    tree = ast.parse(source, filename=filename)
    rules = load_rules()
    context = {"file": filename, "source": source}
    findings = []
    for node in ast.walk(tree):
        for rule in rules:
            findings.extend(rule.check(node, context))
    return sorted(findings, key=lambda f: (f.file, f.line))
