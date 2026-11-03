# fin_logic_cyber_range —— 把业务逻辑风险的推演放进靶场里对账（阶段 11）

阶段 10 给出的是一句话：**"这条路由缺了 `Idempotency_Token`，所以它可以被重放、会重复扣款、
会并发竞争，违反等保三级与 JR/T 0185。"** 这句话是从手工评审出来的图上推出来的，语法正确、逻辑
自洽，但它有一个所有静态结论都有的软肋：**没人见过它发生。**

阶段 11 就让"缺了控制会出什么事"这件事在本地发生一次。做法不是写更多推理，而是把**控制变成
自变量**：同一个剧本、同一个账本，只翻一个开关，看后果是否如推演所说出现。翻开关前出现、翻
开关后消失，推演才算被验证；翻开关前后都一样，那条推演就只是文本。

```
                     ┌─────────────── 同一个剧本（JSON，可评审）───────────────┐
                     │  replay_transfer / concurrent_transfer / unsigned       │
                     └───────────────┬─────────────────────┬──────────────────┘
                                     │                     │
                          ControlSet.vulnerable()   ControlSet.secure()
                                     │                     │
                             ┌───────▼───────┐     ┌───────▼───────┐
                             │ mock 网关(缺控制)│     │ mock 网关(有控制)│
                             │ 127.0.0.1:随机端口│     │ 127.0.0.1:随机端口│
                             └───────┬───────┘     └───────┬───────┘
                                     │  合成账本 + 观测日志   │
                                     └──────────┬──────────┘
                                                ▼
                     oracle.assess → ControlGap ∩ LogicFinding（复用阶段 10 的类）
                                                ▼
                     classify_logic_risk（复用阶段 10 的阶梯）→ 与剧本预测比对
```

**一行结论：** 三个阶段来源里最"贵"的东西（控制要求、后果边、条款边）一行代码没重写；
动态实测用的判定函数和静态推演是**同一个**，所以两者分歧时无法互相掩盖。

---

## 1. 安全边界（这一节优先于其它所有内容）

这个包的唯一目的是**防御性验证**。以下边界是硬约束，写在代码里而不只是写在文档里：

| 约束 | 落地方式 | 违反时的行为 |
| --- | --- | --- |
| 只允许访问本机 mock | `safety.ensure_local_url()` 白名单：`127.0.0.1` / `::1` / `localhost` / `mock-gateway` / `mock-secure-gateway` | `SafetyViolation`（拒绝，且带 `allowed` 候选清单） |
| 只允许 `http`，且端口 `1024..65535` | 同上；`https`、`80`、`userinfo`、`?query` 全部拒绝 | 同上 |
| 只允许绑定回环地址 | `safety.ensure_bind_host()`，`0.0.0.0` 需要显式环境变量 `RANGE_ALLOW_CONTAINER_BIND=1`（只在镜像里设） | `SafetyViolation` |
| 账户 / 金额 / 指令号全是合成值 | `ACC-SYNTH-0001/0002`、`INS-*`、`1000.00` 起始余额；未知账户直接 `LedgerRejection` | 拒绝构造 `Instruction` |
| 请求量有界 | 剧本格式自带上限：`repeat ≤ 8`、`workers ≤ 32`，且**不重试** | 加载剧本时 `DataContractError` |
| 不落盘、不留状态 | 账本、日志全在内存；`docker compose down -v` 或退出进程即清零 | —— |
| 没有真实漏洞利用链 | 没有内存破坏、没有 Hook、没有加固绕过、没有凭证获取；三个剧本只做合法请求的重复与并发 | —— |
| 没有通用攻击工具 | `runner` 只会按剧本发 `POST /mock/v1/transfer`，参数全部来自 JSON | —— |

**被安全软件（如火绒）拦了怎么办。** 本包不联网、不写注册表、不做持久化、不自我解压，
脚本全部是明文 Python（`http.server` / `http.client` / `threading`），被报毒通常是因为"高频
HTTP + 多线程"这一组合的启发式。建议把 `D:\fin_logic_attack_range\fin_logic_cyber_range\`、
`D:\fin_logic_attack_range\scripts\run_logic_range.py` 与解释器 `D:\Anaconda3\python.exe` 加入白名单，
而不是关掉防护。**不要**为了绕过拦截去混淆或加密脚本——那会同时破坏"可评审"这个前提。

---

## 2. 靶场结构

| 文件 | 职责 | 关键设计 |
| --- | --- | --- |
| `safety.py` | 回环白名单守卫 | 三处调用：加载剧本、发请求、起服务；白名单是枚举不是正则 |
| `ledger.py` | 合成账本 + `ControlSet` | `ControlSet` 是自变量；`reconcile` 视角（`duplicated_instructions`）独立于"是否防住" |
| `observability.py` | 观测段 | 每条请求 10 个字段；信号由字段推导（`signals()`），不是靠人读日志 |
| `gateway.py` | mock 网关（`http.server`） | 三条路由；业务判定全部委托给账本，网关自己不做决定 |
| `scenario.py` | 剧本（数据） | 未知键报错（防"打错字变成默认值"）；`endpoint` 只能是路径不能是 URL |
| `runner.py` | 执行器 | `threading.Barrier` 保证"真的同时"；transport 失败是数据不是异常 |
| `oracle.py` | 判定器 | 复用 `ControlGap` / `LogicFinding` / `classify_logic_risk`；未建模的后果单独列为"本体缺口" |
| `report.py` | 报告 | 控制台 / Markdown / JSON；静态 vs 动态按 `(控制, 后果)` 集合做差 |
| `cli.py` | CLI | 退出码 `0/1/2`，与仓库其它脚本一致 |
| `serve.py` | 容器入口 | 唯一"常驻"的运行方式；绑定策略仍走 `safety` |

剧本放在 `data/cyber_range/scenarios/*.json`（与阶段 7–10 的基准图同目录），三个：

| 剧本 | 客户端做了什么 | 预测（vulnerable / secure） |
| --- | --- | --- |
| `replay_transfer` | 同一 `instruction_id` 顺序重发 2 次 | `high` / `none` |
| `concurrent_transfer` | 同一 `instruction_id` 由 8 个线程同时发出 | `critical` / `none` |

---

## 3. 实验设计：为什么这样翻开关

### 3.1 控制变量只允许有一个

`ControlSet` 只有两个布尔字段，`vulnerable()` 与 `secure()` 是它们的两个端点。runner 里
**没有任何 `if mode == "secure"`**：它拿到的是一个 `ControlSet`，账本自己按字段决定分支。这样
两臂不可能"实现上跑偏"——如果哪天真跑偏了，那是账本的分支写错了，而不是两套代码分叉了。

### 3.2 竞态窗口是有意放大的，而且只放大弱势臂

不放大窗口，8 个线程的竞态在开发机上会时快时慢：有时 2 条分录，有时 1 条。**一个会自己消失的
发现等于没发现。** 所以 `SyntheticLedger(window_seconds=...)` 在**未被门锁覆盖的那条路径**上
`sleep`，把"检查-然后-落账"之间的缝撑到 20 ms；`secure` 臂的检查与落账在同一次 `with self._gate`
里完成，放大窗口对它毫无影响（这也是这次实验的一个副产品：**同一个参数对一个臂是噪声、对另一个
臂是稳态**，这本身就是"锁覆盖了整段临界区"的直接证据）。

### 3.3 并发必须是"真的同时"

`ThreadPoolExecutor.map` 是顺序启动的，最后一个线程开始时第一个往往已经做完，"并发"退化成
"重放"。所以 `_fire_together()` 用 `threading.Barrier(workers)` 把 8 个客户端线程全部停住，
再一起放行；barrier 有超时，个别线程卡死也不会拖住整轮。

---

## 4. 观测段：为什么"缺失"要靠对账来抓

阶段 10 已经论证过：**"服务端没做幂等"在 HTTP 观测面上不留痕**。靶场里这一点被具体化成了两列：

| 字段 | 为什么必须有 |
| --- | --- |
| `instruction_id` | 重复检测唯一的 join key；body 解析失败时为空串，这类记录不能参与重复判定 |
| `posted` | 与 `accepted` 分开：secure 臂回 `200` 但**没有**新分录，混在一起就看不出控制生效了 |
| `replayed` | 控制**成功**的证据；报出来是好事，监控不该对它告警 |
| `signature_present` | 只记"有没有带"，从不记值；缺这个字段就分不清"签名错"和"根本没签名" |
| `duplicates_after` | 该请求处理完之后，账上有几条指令是重复的——**运行中的对账视角** |

信号由字段推导，一共四个：

| 信号 | 触发条件 | 性质 |
| --- | --- | --- |
| `duplicate_posting` | 账上某指令 ≥2 条分录 | 侦测（T+1 对账问的正是这个） |
| `unsigned_accepted` | 2xx 且未携带签名头 | 侦测 |
| `idempotent_replay` | 返回了被记住的回执 | 正常——控制生效的正面证据 |
| `rejected_request` | 4xx/5xx | 噪声 |

关键点：`duplicate_posting` 是**侦测控制**，它不需要知道服务端有没有实现幂等，只问账上是否出现
两条分录。这正是"预防失败时仍有最后一层"的现实写法，也解释了为什么 target 环境里对账系统常常
比接口层更早发现问题。

---

## 5. 实跑结果（本机一次真实运行）

```
$ cd D:\fin_logic_attack_range
$ python -m fin_logic_cyber_range --json outputs/cyber_range_report.json \
                                  --markdown outputs/cyber_range_report.md

TBox gate : 0 error(s), 0 warning(s), 0 info(s) against fin-logic-risk v0.1.0
static    : Transfer_API risk=critical, 3 finding(s), 1 control gap(s)
scenarios : 3    arms: vulnerable, secure
```

| 剧本 | 臂 | 请求数 | 实测风险 | 预测风险 | 判定 | 账本结果 |
| --- | --- | ---: | --- | --- | --- | --- |
| `concurrent_transfer` | vulnerable | 8 | **critical** | critical | PASS | 8 条分录，1000.00 → 200.00 |
| `concurrent_transfer` | secure | 8 | none | none | PASS | 1 条分录 |
| `replay_transfer` | vulnerable | 2 | **high** | high | PASS | 2 条分录（`PST-0001`、`PST-0002`） |
| `replay_transfer` | secure | 2 | none | none | PASS | 1 条分录，第二次 `replayed=true` |
| `unsigned_transfer` | vulnerable | 1 | **medium** | medium | PASS | 未带签名仍落账 |
| `unsigned_transfer` | secure | 1 | none | none | PASS | `401 signature_rejected`，0 条分录 |

**6/6 通过。** 代表性证据（原文输出）：

```
finding  : 检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Duplicate_Debit 风险，
           违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。
evidence : 指令 INS-A0000001 产生 2 条分录：PST-0001 记 100.00（回执 RCP-0001）;
           PST-0002 记 100.00（回执 RCP-0002）
```


---

## 6. 静态推演 vs 动态实测：两个方向的差集都有信息

`report.comparison_lines()` 把两边都拆成 `(控制, 后果)` 的集合，然后做三个差集。本机实跑：

```
静态推演        : risk=critical 3 finding(s) from Transfer_API
动态实测        : worst=critical 4 finding(s) across 6 run(s)
两边都成立      : Idempotency_Token/Duplicate_Debit,
                  Idempotency_Token/Race_Condition,
                  Idempotency_Token/Replay_Attack
静态有、本次未复现: （跑全部三个剧本时为 none）
动态有、本体未建模: Signature_Verification/Unsigned_Instruction_Accepted
```

### 6.1 只跑一个剧本时，"未复现"是必然的

只跑 `replay_transfer` 时，动态侧拿不到 `Race_Condition`——顺序重发**不可能**产生竞态，因此
违反的条款只有一条（`Financial_Security_Level_3`），阶梯按"昂贵单位计数"落到 `high` 而不是
`critical`。这不是推演错了，而是**一次运行只能观测到它自己触发的那部分后果**：

> 静态模型是一次运行的**超集**。要覆盖 `critical`，必须同时有并发剧本。

这条结论写进了测试（`test_comparison_names_what_one_run_cannot_reproduce`），因为它太容易
被"6/6 PASS"掩盖掉。

### 6.2 反过来：动力学发现了本体没有边的一条后果

`unsigned_transfer` 在弱势臂上观测到 `Unsigned_Instruction_Accepted`——一个没带签名头的报文
成功把账划走了。而基准图里三条后果边全部挂在 `Idempotency_Token` 上，`Signature_Verification`
**只有 `REQUIRES_CONTROL` 入边、没有 `LEADS_TO_VULNERABILITY` 出边**。于是：

* 靶场不硬塞条款：该后果无对应 `VIOLATES` 边，按阶段 10 阶梯的"无条款"档计 `medium`；
* 同时把它单列为**本体缺口**，并在报告里明说"基准图没有对应边"。

这是一条可回填的改进项，写法也只有两种，二选一：

```json
{"source_concept": "Signature_Verification", "target_concept": "Unsigned_Instruction_Accepted",
 "relation_type": "LEADS_TO_VULNERABILITY", "evidence": "动态实测：无签名头请求被受理并落账"}
{"source_concept": "Unsigned_Instruction_Accepted", "target_concept": "JR_T_0185_API_Spec",
 "relation_type": "VIOLATES", "evidence": "接口安全规范要求资金类接口报文完整性可校验"}
```

回填之后，同一个剧本的预测应当从 `medium` 变成 `high`——**而今天它确实是 `medium`，报告里
写着这是缺口而不是通过。** 一个能指出自己本体缺口的靶场，比一个只会亮绿灯的靶场有用。

---

## 7. 怎么跑

```powershell
# 全量：3 个剧本 × 2 个臂，并写 JSON / Markdown
cd D:\fin_logic_attack_range
python -m fin_logic_cyber_range --json outputs\cyber_range_report.json `
                                                   --markdown outputs\cyber_range_report.md

# 只跑一个剧本的一个臂
python -m fin_logic_cyber_range --scenario replay_transfer --mode secure

# 看每一条请求的观测记录
python -m fin_logic_cyber_range --mode vulnerable --verbose

# 等价入口（scripts/ 里的薄壳）
python scripts\run_logic_range.py --mode both
```

CLI 参数：

| 参数 | 默认 | 含义 |
| --- | --- | --- |
| `--scenario NAME` | 全部 | 只跑该 slug（可重复） |
| `--scenario-dir DIR` | `data/cyber_range/scenarios` | 剧本目录 |
| `--mode vulnerable\|secure\|both` | `both` | 跑哪个臂 |
| `--window-ms MS` | `20` | 弱势臂的竞态窗口，`0..500` |
| `--graph PATH` / `--api NAME` | `data/fin_logic_micro_graph.json` / `Transfer_API` | 静态对比用图 |
| `--no-static` | 关 | 跳过静态对比 |
| `--no-validate` | 关 | 跳过 TBox 闸门（不建议） |
| `--json` / `--markdown` | 不写 | 产物路径 |
| `--verbose` / `--quiet` | 关 | 打印每条观测记录 / 只打印判定行 |

退出码：`0` 全部（剧本 × 臂）与预测一致；`1` 有组合不一致，或基准图违反 TBox（拒绝对比）；`2`
剧本读不出来、图读不出来、起点非法、参数越界。

### 演示：先开靶场，再打一场（`scripts/attack_demo.py`）

上面的 CLI 是"一次性跑完 N 个剧本再出报告"的科研形态。要**看着靶场先起来、再被一步步打**，
用演示入口：

```powershell
python scripts\attack_demo.py             # 开靶场 + 4 阶段攻击 + 对照 + 判定
python scripts\attack_demo.py --dry-run   # 只打印计划与边界自检，不开 socket
python scripts\attack_demo.py --workers 4 --no-write
```

它和 CLI 用的是**同一批零件**：`MockGatewayServer` 起臂、`post_instruction` 发包、
`assess` 判定、`classify_logic_risk` 打分；只有 GET（侦察 `/mock/v1/ledger`）是演示自己补的 15 行，
因为它同样先过 `ensure_local_url()` 再建连接——演示脚本不是安全边界上的例外。

流程与本次实跑（`--workers 6`，退出码 0，7/7 自检通过）：

| 阶段 | 动作 | vulnerable 臂 | secure 臂 |
| --- | --- | --- | --- |
| 1 | 侦察：`GET /health` + `GET /ledger` | `mode=vulnerable`，0 分录 | `mode=secure`，0 分录 |
| 2 | 基线：一笔正常指令 `INS-ATK-9901` | 200，`PST-0001` | 200，`PST-0001` |
| 3 | 攻击 A 重放：`INS-ATK-9902` 连发 3 次 | 200×3，**3 条分录** | 200×3，第 2/3 次 `replayed=true`，1 条分录 |
| 4 | 攻击 B 并发：`INS-ATK-9903` 6 线程同刻释放 | 200×6，**6 条分录**（28 ms 内） | 200×6，仅 1 条分录，5 次 `replayed=true` |
| 5 | 攻击 C 无签名：不发 `X-Lab-Signature` | 200，**受理并落账** | **401 `signature_rejected`** |
| 6 | 对账 | 11 条分录，重复指令 `INS-ATK-9902/9903`，余额 1000.00→600.00 | 3 条分录，无重复，余额 920.00 |
| 7 | 判定 | `observed=critical`（4 条 finding + 1 条本体缺口） | `observed=none` |

并发那一步的屏幕上会出现"线程 #1 落了 `PST-0007`、线程 #2 落了 `PST-0005`"这种乱序——**这就是真的
同时**：分录号由账本锁的获取顺序决定，不由线程编号决定。排序打印反而会掩盖这件事，所以演示按线程
编号原样打印。

证据落在 `outputs/attack_demo.json`（响应、账本快照、两份 assessment、7 条自检结论），
可用 `--no-write` 关掉。

要把这场演示写成可交付的 Word 报告，用：

```powershell
python scripts\build_attack_report_doc.py            # 生成 .docx 并另存 .doc 到桌面
python scripts\build_attack_report_doc.py --no-convert  # 只出 .docx（不需要 Word）
```

报告里的数字全部取自上面两次真实运行的产物（`outputs/cyber_range_report.md`、`outputs/attack_demo.json`、
`logs/_demo_run2.txt`），生成脚本本身只做排版。

**为什么这不会惊动杀软（本机火绒 `HipsDaemon`/`HipsTray` 与 Defender 同时在跑，实跑无告警）**：
没有可执行物（不写 `.exe/.bat/.ps1`）、没有 `subprocess`/shell、不碰注册表/服务/计划任务、
唯一的磁盘写入是上面那个 JSON、目标恒为回环（`ensure_local_url()` 每次请求前检查，公网地址直接
`SafetyViolation`）、3 个已知路由且没有扫描、源码全明文（无 `eval`/`base64`/打包壳）。
请求量也写死：`--workers` 上限 8（剧本格式允许 32，这里更低），单臂 `workers + 5` 个 POST，
不重试、不循环。

### 容器化（可选，本机未安装 Docker）

`deploy/cyber_range/` 提供 `docker-compose.yml` 与 `Dockerfile`：两个服务（弱势 / 防护臂）挂在
`internal: true` 的 `range` 网络上，宿主端口只发布到 `127.0.0.1:18080` 与 `127.0.0.1:18081`，
`read_only` + `cap_drop: [ALL]` + `mem_limit` + `pids_limit`。

> 本机 `docker` 命令不可用，所以这条路径属于**配置已交付、未在本机实跑**。日常验证用上面的进程内
> mock（同样只走 `127.0.0.1`）。容器里之所以允许 `0.0.0.0`，是因为 Docker 的端口转发到不了容器
> 的 loopback；这个许可由镜像内的 `RANGE_ALLOW_CONTAINER_BIND=1` 显式开启，宿主侧再靠 compose

---

## 8. 这个靶场**没有**证明什么

写清楚边界，比多写一个剧本更有价值：

1. **它不是对真实系统的评估。** mock 网关是"按我对缺失控制的理解"写的：因此它验证的是
   **推演链条的自洽性**（缺控制 → 后果 → 条款 → 分级），不是"某银行 App 存在该缺陷"。
   要落到真实对象，得在**书面授权**范围内、针对自家系统、按同一剧本结构复测。
2. **竞态窗口是人为放大的。** 20 ms 不代表真实系统的时间窗；它只保证复现稳定。真实系统里同一个
   缺陷可能只在高峰期出现百万分之一，那属于另一个问题（可观测性 + 长尾复现），不是本靶场的结论。
3. **`oracle` 的映射表是人写的。** `CONTROL_CONSEQUENCES` / `FLAW_CLAUSES` 是基准图边的动态镜像，
   由我抄写；抄错就会得出"看起来对"的结论。缓解办法是让两边共用一个 `classify_logic_risk`，并把
   差集打印出来——但**映射本身仍需人工评审**。
4. **合成数据无法暴露数据正确性问题。** 账本只有两个账户、一种币种、没有清算/对账周期、没有
   冲正，也没有手续费与限额策略。真实业务逻辑风险里很大一部分长在这些地方。
5. **它不替代渗透测试，也不替代代码评审。** 它只机械化"缺失控制"这一条推理链，这正是阶段 10 §1.4
   划定的适用范围。

---

## 9. 测试

```powershell
cd D:\fin_logic_attack_range
# 本域
python -m pytest fin_logic_cyber_range --cov=fin_logic_cyber_range --cov-report=term-missing
# 115 passed，总覆盖率 98%（1663 语句 / 36 未覆盖）

# 全量（框架 + 阶段 7–11，pyproject 的 testpaths 已含本域）
cd ontology_builder
python -m pytest --cov=ontology_builder --cov=fin_logic_risk --cov-fail-under=95
```

本域覆盖率（`--cov=fin_logic_cyber_range`）：

| 文件 | 语句 | 覆盖率 |
| --- | ---: | ---: |
| `safety.py` | 61 | 97% |
| `ledger.py` | 183 | 99% |
| `observability.py` | 77 | **100%** |
| `gateway.py` | 143 | 95% |
| `scenario.py` | 181 | 96% |
| `oracle.py` | 111 | 99% |
| `runner.py` | 111 | 94% |
| `report.py` | 98 | 98% |
| `cli.py` | 111 | 99% |
| `serve.py` | 46 | 98% |
| `__init__.py` / `__main__.py` | 11 / 4 | 100% / 未计入（`-m` 入口，函数体仅一行） |

测试覆盖的"容易写漏"的边界：

* **安全边界是参数化断言的**：`http://example.com/...`、`http://8.8.8.8:8080/x`、
  `http://bank.example.net:8443/...`、`https://`、`ftp://`、`user:pass@`、端口 `80`、
  `?debug=1`、端口 `70000`、空串、`None` —— 每一种都必须抛 `SafetyViolation`；
* **绑定地址**：`0.0.0.0` 默认拒绝，只有 `RANGE_ALLOW_CONTAINER_BIND=1` 时才放行（容器镜像里设）；
* **控制生效的正面证据**：secure 臂第二次请求必须 `replayed=True` 且 `posted=False`；
* **观测段并发**：20 个线程同时 append，`seq` 必须是 `1..20` 各一次；
* **一次运行 ≠ 静态模型**：`test_comparison_names_what_one_run_cannot_reproduce` 钉住"顺序重放
  复现不了 `Race_Condition`"这条结论；
* **预测落空要红**：一个把 `expect_vulnerable` 写成 `critical` 但只发一次请求的剧本必须退出码 1。

---

## 10. 与阶段 10 的关系，以及这次迁移的代价

| 维度 | 阶段 10（静态推演） | 阶段 11（动态验证） |
| --- | --- | --- |
| 输入 | 手工评审过的图（`LACKS_CONTROL` 是"有"的边） | 剧本 + 一个 `ControlSet` |
| 推理形式 | 集合差 `required ∩ missing` | 集合差 `missing_controls ∩ observed_flaws` |
| 判定函数 | `classify_logic_risk` | **同一个** `classify_logic_risk` |
| 结论形态 | 一句话（路由 / 控制 / 后果 / 条款 / 补法） | 同一句话 + 分录级证据 |
| 能发现本体缺口吗 | 不能（它只有图） | **能**（见 §6.2） |

迁移成本：`fin_logic_risk` **0 行改动**；`ontology_builder` **0 行改动**（只在 `pytest.ini` 的
`testpaths` 里追加了本域，好让同一条命令跑全量）；新增 10 个模块（`safety` / `ledger` /
`observability` / `gateway` / `scenario` / `runner` / `oracle` / `report` / `cli` / `serve`）+
1 个测试文件 + 3 个剧本 + 1 份部署配置。这一次没有新增词汇表成员——**靶场不扩展本体，它只检验
本体**，所以词表的第 11 次"扩张"是 0，这本身就是共享词汇表收敛的又一个证据。

下一步（可选，不在本次范围）：把 `data/cyber_range/scenarios/*.json` 换成"从真实接口描述生成的
剧本"，或者给 `observability` 接一个最小日志管道（Filebeat/OTel 形态），验证"侦测信号能否变成
告警"。任何一项都必须在**授权环境、自家系统、书面范围**内做。



