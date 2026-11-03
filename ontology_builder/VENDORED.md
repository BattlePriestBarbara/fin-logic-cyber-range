# 这里是 vendored 子集，不是完整的 ontology_builder

本目录只包含靶场真正 import 到的 9 个文件，来自上游研究工作区里的 `ontology_builder`
（一个面向知识图谱构建的框架包，完整版含抽取、统计、KGE 等六个阶段）。之所以裁剪而不是整包
引入：完整包有 119 个文件 / 5.4 MB，其中与本仓库无关的模块还会拖进 numpy、torch、matplotlib。

| 文件 | 为什么需要 |
| --- | --- |
| `schema.py` | `KnowledgeGraph` / `OntologyConcept` / `Relationship` / `ConceptCategory` —— 基准图的数据模型 |
| `core/errors.py` | `DataContractError` / `OntologyViolationError`：剧本校验、账本校验抛的就是它们 |
| `core/contracts.py` | `Severity` 等值对象（`core/__init__.py` 会 re-export） |
| `core/reports.py`、`core/ports.py` | 同上：`core/__init__.py` 一 import 就连带 import 这两个 |
| `ontology/tbox.py` | `OntologySchema` / `RelationRule` / `PALANTIR_TBOX`：边的准入规则 |
| `ontology/constraints.py` | 10 个 `Constraint` 实现 |
| `ontology/validator.py` | `OntologyValidator` / `ValidationPolicy`：靶场开跑前先过 TBox 闸门 |

## 改动规则

* **不要在这里加新模块。** 需要框架里别的东西时，正确的做法是从上游同步，而不是在本仓库里
  分叉一份实现。
* 这些文件的相对 import 未作任何修改（`from ontology_builder.core.errors import ...` 等原样
  保留），所以 `import ontology_builder` 的行为与上游一致：只拉起 pydantic + networkx。
* 只被裁掉的部分（`extractor.py`、`pipeline.py`、`stats_analysis.py`、`kge_*.py`、`services/`、
  各 `test_*.py`）在本仓库里没有调用方。

## 上游的测试去哪了

`ontology_builder` 的 20 个测试文件测的是被裁掉的模块，所以没有随代码一起进来。
被保留的这几块在上游有自己的测试（`test_schema.py` / `test_constraints.py` /
`test_validator.py` / `test_tbox.py` / `test_core.py`），本仓库的靶场测试会以**使用者**的身份
覆盖它们：剧本加载、TBox 闸门、账本记账都在 `fin_logic_cyber_range/test_range.py` 里被反复调用。
