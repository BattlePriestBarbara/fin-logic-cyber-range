# 金融业务逻辑靶场报告

全部目标为 `127.0.0.1` 上的 mock 网关（或 compose 内部服务名），账户、金额、指令号均为合成数据。

## 1. 逐臂结果

| 剧本 | 臂 | 请求数 | 实测风险 | 预测风险 | 判定 |
| --- | --- | ---: | --- | --- | --- |
| `concurrent_transfer` | vulnerable | 8 | **critical** | critical | PASS |
| `concurrent_transfer` | secure | 8 | **none** | none | PASS |
| `replay_transfer` | vulnerable | 2 | **high** | high | PASS |
| `replay_transfer` | secure | 2 | **none** | none | PASS |
| `unsigned_transfer` | vulnerable | 1 | **medium** | medium | PASS |
| `unsigned_transfer` | secure | 1 | **none** | none | PASS |

## 2. 发现与证据

### `concurrent_transfer` / vulnerable - 双击 / 重试风暴下同一指令并发提交

- 缺失控制：`Idempotency_Token`, `Signature_Verification`
- 观测到的问题类型：`Duplicate_Debit`, `Race_Condition`
- 结论句：检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Duplicate_Debit 风险，违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。
- 结论句：检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Race_Condition 风险，违反 JR_T_0185_API_Spec，建议增加唯一请求 ID 校验。
- 证据：指令 INS-B0000002 产生 8 条分录：PST-0001 记 100.00（回执 RCP-0001）; PST-0002 记 100.00（回执 RCP-0002）; PST-0003 记 100.00（回执 RCP-0003）; PST-0004 记 100.00（回执 RCP-0004）; PST-0005 记 100.00（回执 RCP-0005）; PST-0006 记 100.00（回执 RCP-0006）; PST-0007 记 100.00（回执 RCP-0007）; PST-0008 记 100.00（回执 RCP-0008）

### `concurrent_transfer` / secure - 双击 / 重试风暴下同一指令并发提交

- 缺失控制：无
- 观测到的问题类型：无

### `replay_transfer` / vulnerable - 同一笔转账指令被原样重放两次

- 缺失控制：`Idempotency_Token`, `Signature_Verification`
- 观测到的问题类型：`Duplicate_Debit`, `Replay_Attack`
- 结论句：检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Duplicate_Debit 风险，违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。
- 结论句：检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Replay_Attack 风险，违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。
- 证据：指令 INS-A0000001 产生 2 条分录：PST-0001 记 100.00（回执 RCP-0001）; PST-0002 记 100.00（回执 RCP-0002）

### `replay_transfer` / secure - 同一笔转账指令被原样重放两次

- 缺失控制：无
- 观测到的问题类型：无

### `unsigned_transfer` / vulnerable - 缺少签名头的转账请求仍被受理

- 缺失控制：`Idempotency_Token`, `Signature_Verification`
- 观测到的问题类型：`Unsigned_Instruction_Accepted`
- 本体缺口：`Unsigned_Instruction_Accepted`（基准图中没有对应的 `LEADS_TO_VULNERABILITY` / 条款边）
- 结论句：检测到 Transfer_API 缺失 Signature_Verification，推导出存在 Unsigned_Instruction_Accepted 风险，违反 未映射的合规条款，建议补齐签名校验。
- 证据：请求 #1 未携带签名头仍被受理并落账

### `unsigned_transfer` / secure - 缺少签名头的转账请求仍被受理

- 缺失控制：无
- 观测到的问题类型：无

## 3. 静态推演 vs 动态实测

- 静态推演        : risk=critical 3 finding(s) from Transfer_API
- 动态实测        : worst=critical 4 finding(s) across 6 run(s)
- 两边都成立      : Idempotency_Token/Duplicate_Debit, Idempotency_Token/Race_Condition, Idempotency_Token/Replay_Attack
- 静态有、本次未复现: none
- 动态有、本体未建模: Signature_Verification/Unsigned_Instruction_Accepted

## 4. 结论

- 6/6 个（剧本 × 臂）组合与本体预测一致，最高实测风险 **critical**。

