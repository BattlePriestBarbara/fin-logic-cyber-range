# 金融业务逻辑靶场 · fin_logic_attack_range

> 一句话：把静态推演说出来的"这条转账接口缺了 `Idempotency_Token`，所以能被重放、会重复扣款、会
> 并发竞争"放到一个 **127.0.0.1 上、账本全是合成数据** 的小靶场里跑一遍，翻一个开关看后果是否
> 真的出现。翻开关前出现、翻开关后消失，这条推演才算被验证；前后都一样，它就只是文本。

本仓库是一次完整实验的**可复现切片**：靶场代码、三个可评审剧本、手工基准图、被检验的静态层、
上游框架的最小 vendored 子集、两次真实运行的证据，以及由这些证据排版的 Word 报告。

---

## 0. 这是什么 / 这不是什么

| 是 | 不是 |
| --- | --- |
| 业务逻辑缺陷的**受控复现**：只重复、只并发、只省掉签名头 | 不是攻击工具：没有内存破坏、没有 Hook、没有加固绕过、没有凭证获取 |
| 一个**可证伪**的实验：剧本自带预测，实测与预测不一致就以退出码 1 结束 | 不是扫描器：不发现目标、不枚举接口、不解析二进制 |
| 全部流量指向 `127.0.0.1` 上随机端口的 mock 网关 | 不是对真实系统的评估：不访问任何真实主机，不含任何真实客户数据 |
| 判定函数与静态推演**共用同一个**（`classify_logic_risk`），两边分歧时无法互相掩盖 | 不是第二套评分表：`fin_logic_risk` 一行没改 |

账户是 `ACC-SYNTH-0001/0002`，起始余额 `1000.00`，金额只用 `10 / 20 / 30 / 50`，指令号是
`INS-*`——全是构造值。

---

## 1. 目录结构

```
fin_logic_attack_range/
├── fin_logic_cyber_range/        靶场本体：13 个模块 + 115 个测试 + 设计文档（README.md）
├── fin_logic_risk/               被检验的静态层：tbox.py + risk_reasoner.py（5 个类 + 5 个关系）
├── ontology_builder/             vendored 子集（9 文件）：图模型 + 约束层 + 类型化错误，见 VENDORED.md
├── data/
│   ├── fin_logic_micro_graph.json   手工基准图：9 概念 / 10 边
│   └── cyber_range/scenarios/       3 个剧本（JSON）：并发、重放、无签名
├── deploy/cyber_range/           可选容器化：internal 网络 + 只发布 127.0.0.1
├── scripts/
│   ├── attack_demo.py               开靶场 + 三段攻击（重放 / 并发 / 无签名）+ 两臂对照 + 判定
│   ├── run_logic_range.py           剧本全量的薄壳入口（等价于 `python -m fin_logic_cyber_range`）
│   └── build_attack_report_doc.py   把证据排成 Word 报告（.docx → Word COM → .doc）
├── outputs/                      本轮运行的证据：attack_demo.json / cyber_range_report.{json,md}
├── logs/_demo_run2.txt           攻击演示的原始控制台记录
├── docs/                         报告成稿：金融业务逻辑靶场攻击模拟报告.doc
├── pyproject.toml               元数据 + pytest 配置（testpaths 只含靶场测试）
└── LICENSE                       MIT
```

> `outputs/` 与 `logs/` 通常是运行产物、不入库；这里**故意放行了这三个文件加一份日志**，因为
> 报告里的每一个数字都要能落回证据。其余产物仍被 `.gitignore` 忽略。

---

## 2. 快速开始

依赖只有两个库：`pydantic>=2`、`networkx>=3`（生成报告额外需要 `python-docx`）。
不需要安装本仓库也能跑——命令都在仓库根执行：

```powershell
cd D:\fin_logic_attack_range

# 1) 全量剧本：3 个剧本 × 2 个臂，写 JSON / Markdown 证据
python -m fin_logic_cyber_range --json outputs\cyber_range_report.json `
                                --markdown outputs\cyber_range_report.md

# 2) 只看一个剧本的一个臂（vulnerable / secure）
python -m fin_logic_cyber_range --scenario replay_transfer --mode secure

# 3) 攻击演示：先开靶场，再按 4 个阶段打，两臂对照，最后判定
python scripts\attack_demo.py

# 4) 只看计划与边界自检，不创建任何 socket
python scripts\attack_demo.py --dry-run

# 5) 重新生成 Word 报告（不需要 Word 时用 --no-convert 只出 .docx）
python scripts\build_attack_report_doc.py --out-dir docs

# 6) 测试
python -m pytest
```

想用 `pip` 安装也行：`pip install -e ".[report]"`，之后 `fin-logic-range --mode both` 等价于
第 1 步。

---

## 3. 一次真实运行的结果（就在这个仓库里跑出来的）

```
$ python -m fin_logic_cyber_range --json outputs/cyber_range_report.json \
                                  --markdown outputs/cyber_range_report.md

TBox gate : 0 error(s), 0 warning(s), 0 info(s) against fin-logic-risk v0.1.0
static    : Transfer_API risk=critical, 3 finding(s), 1 control gap(s)
scenarios : 3    arms: vulnerable, secure
...
结论      : 6/6 run(s) matched; worst observed critical      (退出码 0)
```

| 剧本 | 臂 | 请求数 | 实测风险 | 预测风险 | 判定 | 账本结果 |
| --- | --- | ---: | --- | --- | --- | --- |
| `concurrent_transfer` | vulnerable | 8 | **critical** | critical | PASS | 8 条分录，1000.00 → 200.00 |
| `concurrent_transfer` | secure | 8 | none | none | PASS | 1 条分录 |
| `replay_transfer` | vulnerable | 2 | **high** | high | PASS | 2 条分录（`PST-0001`、`PST-0002`） |
| `replay_transfer` | secure | 2 | none | none | PASS | 1 条分录，第二次 `replayed=true` |
| `unsigned_transfer` | vulnerable | 1 | **medium** | medium | PASS | 未带签名仍落账 |
| `unsigned_transfer` | secure | 1 | none | none | PASS | `401 signature_rejected`，0 条分录 |

**6/6 通过，退出码 0。** 把这次重跑的结果与入库的 `outputs/cyber_range_report.md` 逐行对比：
**0 行差异**——报告里的数字不是抄来的，是可以被任何一台机器重新跑出来的。

攻击演示（`python scripts\attack_demo.py`，退出码 0）走的是另一条路径：先开靶场，再按 `[1]` 侦察 →
`[2]` 基线 → `[3]` 重放 → `[4]` 并发风暴 → `[5]` 无签名 → `[6]` 攻击后对账 → `[7]` 判定 的顺序打
一遍（三段攻击 A/B/C，每段在弱势臂与强势臂上各跑一次），最后做 7 条自检：

| 臂 | 请求数 | 判定 | 账本 | 自检 |
| --- | ---: | --- | --- | --- |
| vulnerable | 11 | **critical** | 11 条分录，1000.00 → **600.00** | 7/7 OK |
| secure | 11 | none | 3 条分录，1000.00 → 920.00 | 7/7 OK |

两臂的余额差 `320.00` 可以从账本直接加出来，不是估的：`2×20`（重放的重复扣款）+ `5×50`（并发
风暴里被放大的重复扣款）+ `30`（无签名指令在弱势臂落账、在强势臂被 401 拒掉）。

代表性证据（原文，`outputs/cyber_range_report.md`）：

```
finding  : 检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Duplicate_Debit 风险，
           违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。
evidence : 指令 INS-A0000001 产生 2 条分录：PST-0001 记 100.00（回执 RCP-0001）;
           PST-0002 记 100.00（回执 RCP-0002）
```

---

## 4. 静态推演 vs 动态实测：两个方向的差集都有信息

`report.comparison_lines()` 把两边都拆成 `(控制, 后果)` 的集合再做三个差集。本仓库实测：

```
静态推演        : risk=critical 3 finding(s) from Transfer_API
动态实测        : worst=critical 4 finding(s) across 6 run(s)
两边都成立      : Idempotency_Token/Duplicate_Debit,
                  Idempotency_Token/Race_Condition,
                  Idempotency_Token/Replay_Attack
静态有、本次未复现: none
动态有、本体未建模: Signature_Verification/Unsigned_Instruction_Accepted
```

**"未复现"是有条件的。** 只跑 `replay_transfer` 一个剧本时，动态侧拿不到 `Race_Condition`——
顺序重发**不可能**产生竞态，违反的条款只剩一条，阶梯按"昂贵单位计数"落到 `high` 而不是
`critical`。这不是推演错了，而是**一次运行只能观测到它自己触发的那部分后果**：静态模型是一次
运行的超集。这条结论固定在测试里（`test_comparison_names_what_one_run_cannot_reproduce`），
因为它太容易被"6/6 PASS"掩盖掉。

**"本体未建模"才是真正的收获。** `unsigned_transfer` 在弱势臂上观测到
`Unsigned_Instruction_Accepted`——没带签名头的报文成功把账划走了；而基准图里
`Signature_Verification` **只有 `REQUIRES_CONTROL` 入边、没有 `LEADS_TO_VULNERABILITY` 出边**。
于是靶场不硬塞条款：该后果按"无条款"档计 `medium`，并把它单列为**本体缺口**。回填一条边之后，
同一个剧本的预测应当从 `medium` 变成 `high`——**而今天它确实是 `medium`，报告里写的是缺口而不是
通过**。一个能指出自己本体缺口的靶场，比一个只会亮绿灯的靶场有用。

---

## 5. 安全边界（这一节优先于其它所有内容）

这个靶场的唯一目的是**防御性验证**，所以边界写在代码里，而不只是写在文档里：

| 约束 | 落地方式 | 违反时的行为 |
| --- | --- | --- |
| 只允许访问本机 mock | `safety.ensure_local_url()` 白名单：`127.0.0.1` / `::1` / `localhost` / `mock-gateway` / `mock-secure-gateway` | `SafetyViolation`，并附带允许清单 |
| 只允许 `http`，端口 `1024..65535` | 同上；`https`、`80`、`userinfo`、`?query` 全部拒绝 | 同上 |
| 只允许绑定回环地址 | `safety.ensure_bind_host()`；`0.0.0.0` 需要显式环境变量 `RANGE_ALLOW_CONTAINER_BIND=1`（只在镜像里设） | `SafetyViolation` |
| 账户 / 金额 / 指令号全合成 | `ACC-SYNTH-0001/0002`、`INS-*`、起始余额 `1000.00`；未知账户直接 `LedgerRejection` | 拒绝构造 `Instruction` |
| 请求量有界 | 剧本格式自带上限：`repeat ≤ 8`、`workers ≤ 32`，且**不重试** | 加载剧本时 `DataContractError` |
| 不落盘、不留状态 | 账本与观测日志都在内存；进程退出即清零 | —— |
| 没有真实利用链 | 无内存破坏、无 Hook、无加固绕过、无凭证获取；三个剧本只做合法请求的重复与并发 | —— |
| 没有通用攻击工具 | `runner` 只会按剧本发 `POST /mock/v1/transfer`，参数全部来自 JSON | —— |

被安全软件拦了怎么办：本仓库不联网、不写注册表、不做持久化、不自我解压，脚本全是明文 Python
（`http.server` / `http.client` / `threading`）。若被"高频 HTTP + 多线程"的启发式误报，请把本
仓库目录与 `python` 解释器加入白名单，而不是关掉防护——**不要**为了绕过拦截去混淆或加密脚本，
那会同时破坏"可评审"这个前提。

---

## 6. 证据与报告

| 文件 | 内容 | 谁产生 |
| --- | --- | --- |
| `outputs/cyber_range_report.md` | 6 个（剧本 × 臂）的判定、结论句、账本证据、三向差集 | `python -m fin_logic_cyber_range` |
| `outputs/cyber_range_report.json` | 同一份结果的机器可读版 | 同上 |
| `outputs/attack_demo.json` | 4 阶段攻击的响应、账本快照、两份 `assessment`、7 条自检结论 | `python scripts\attack_demo.py` |
| `logs/_demo_run2.txt` | 演示的原始控制台记录（含边界自检原文） | 同上 |
| `docs/金融业务逻辑靶场攻击模拟报告.doc` | 10 章 + 2 个附录、16 张表的 Word 报告，正文里每个数字都能回溯到上面四份文件 | `python scripts\build_attack_report_doc.py` |

报告生成脚本只做排版：不联网、不读注册表；`.docx` 由 python-docx 排版，最后一步用 Word COM
另存为原生 `.doc`（`wdFormatDocument = 0`）。没装 Word 时加 `--no-convert` 只出 `.docx`，
内容完全一致。

---

## 7. 测试

```
$ python -m pytest
115 passed in 12.52s

$ python -m pytest fin_logic_cyber_range --cov=fin_logic_cyber_range
TOTAL   1662   36   98%
```

靶场包 13 个模块、1662 条语句，36 条未覆盖（多为防御性分支：非法端口、绑定地址被放宽、剧本
越界等"本该抛异常"的路径）。测试与源码同目录（`fin_logic_cyber_range/test_range.py`），这在上游
工作区是约定：一个领域的测试跟着领域走，不集中到 `tests/`。

本机实测环境：Windows 10 + Python 3.12.7、pydantic 2.13.4、networkx 3.3、pytest 7.4.4、
python-docx 1.2.0、Word 12.0（仅用于 `.doc` 转换）。

---

## 8. 依赖、来源与许可

| 依赖 | 用途 | 必需 |
| --- | --- | --- |
| `pydantic>=2` | 剧本、账本、观测记录的数据契约 | 是 |
| `networkx>=3` | `KnowledgeGraph` 的底层图结构（TBox 闸门要遍历它） | 是 |
| `python-docx>=1.1` | 生成 Word 报告 | 否（`.[report]`） |

**来源声明。** `ontology_builder/` 是从同一作者的上游研究工作区裁剪的 9 文件 vendored 子集
（见 `ontology_builder/VENDORED.md`），未改动任何 import；`fin_logic_risk/` 是那个工作区里的
静态推理层，代码未改动，其上游测试因 import 另外两个不在本仓库的领域而未随行。两处与本仓库
原创代码一样以 MIT 发布。

**许可。** MIT，见 `LICENSE`。基准图里出现的 `JR_T_0185_API_Spec`、`Financial_Security_Level_3`
等只是**条款名称字符串**，用于把技术后果映射到条款编号，不包含任何标准正文。

---

## 9. 已知限制（请不要把它们读成"通过"）

* **覆盖面很小**：只覆盖 2 个控制、1 个接口（`Transfer_API`）、3 个剧本。`Signature_Verification`
  的其它后果（如 `Tampered_Instruction`）还没有剧本。
* **竞态窗口是被有意放大的**（20 ms）。这是实验设计，为了让"检查—落账"的间隙可被稳定观测；
  真实系统的窗口宽度取决于实现，需要单独测量，不能拿这 20 ms 去估。
* **签名是演示用的**：截断 SHA-256，足以区分"有签名 / 无签名 / 签名错"，但**不是**生产可用的
  密码学方案（无密钥管理、无时间窗、无 nonce 去重）。
* **容器化未实跑**：`deploy/cyber_range/` 的 compose 配置已交付，但编写它的机器没装 Docker，
  属"配置已交付、未在本机验证"。
* **演示里的 GET 侦察是演示脚本补的**：`runner` 只有 POST，读账本路由的十几行由
  `attack_demo.py` 自行实现——但它同样先过 `ensure_local_url()`，不是边界上的例外。
* **只证明链条自洽且可复现**，**不证明**任何真实系统存在漏洞。文本不涉及真实客户数据，也不
  指向任何真实主机。


