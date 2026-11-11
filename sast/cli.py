"""命令行入口骨架。"""
import argparse
import sys

from .analyzer import analyze_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sast", description="Python AST 静态安全分析器")
    parser.add_argument("path", help="待扫描的文件或目录")
    parser.add_argument("--rule", help="仅启用指定规则 ID")
    parser.add_argument("--severity", choices=["error", "warning", "info"], help="最低严重级别")
    parser.add_argument("--sarif", action="store_true", help="输出 SARIF 2.1.0 JSON")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # TODO: 目录递归、规则筛选、SARIF 输出、退出码尚未实现
    with open(args.path, "r", encoding="utf-8") as fh:
        findings = analyze_source(fh.read(), args.path)
    for f in findings:
        print(f"{f.file}:{f.line} [{f.rule_id}] {f.message}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
