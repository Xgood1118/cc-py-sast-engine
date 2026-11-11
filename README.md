# py-sast-engine

基于 Python AST 的静态安全分析器（骨架）。当前仅实现硬编码密钥规则，跨函数污点分析、SARIF 输出、目录递归扫描待实现。无第三方运行依赖，Python 3.10+。

运行：

```
python -m sast.cli samples/vulnerable.py
```

测试：

```
python -m pytest tests/
```
