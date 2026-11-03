# -*- coding: utf-8 -*-
"""开一个本地靶场，然后对它模拟一次金融业务逻辑攻击（合成数据，仅回环）。

三步走
------
1. **开靶场**：在 ``127.0.0.1`` 上拉起 mock 网关的 vulnerable 臂（两个控制都缺），
   打印 ``/mock/v1/health`` 的真实应答作为"靶场确实在跑"的证据；
2. **打靶**：侦察 → 基线转账（证明正常路径是好的）→ 重放 → 并发重试风暴 →
   无签名注入，每一步都经 :func:`~fin_logic_cyber_range.runner.post_instruction`，
   也就是剧本用的同一条客户端代码，没有第二套"演示专用"发包逻辑；
3. **判定**：把 postings 与 access 交给
   :func:`~fin_logic_cyber_range.oracle.assess`，用阶段 10 的阶梯打分，再把同一套攻击
   打在 secure 臂上做对照——"一臂是噪声、另一臂是稳态"必须在同一次运行里看得见。

为什么火绒不会拦
----------------
杀软拦的是「可执行物 / 持久化 / 外联 / 混淆」这四类，这份演示四样都没有：

* 不写 ``.exe`` / ``.bat`` / ``.ps1``，没有 ``subprocess`` / ``os.system`` / shell 调用；
* 不碰注册表、计划任务、启动项、``%TEMP%``；唯一的磁盘写入是 ``outputs/attack_demo.json``
  （纯文本证据，可用 ``--no-write`` 关掉）；
* 目标恒为回环：:func:`~fin_logic_cyber_range.safety.ensure_local_url` 在每次请求前检查，
  公网地址/域名/https 一律抛 ``SafetyViolation``；没有 DNS、没有出站、没有端口扫描，
  只有 3 个已知路由；
* 源码全明文，无 ``eval`` / ``exec`` / ``base64`` / 打包壳。

请求量也是写死的：``--workers`` 上限 8（剧本格式本身允许 32，这里刻意更低），单次运行总计
``workers + 5`` 个请求，阶段之间留 150ms 间隔，不重试、不循环、不并发超过 8。

退出码
------
``0`` 自检全通过（漏洞复现 + 对照臂干净）；``1`` 有自检不通过；``2`` 参数非法。

示例
----
    python scripts/attack_demo.py
    python scripts/attack_demo.py --dry-run          # 只打印计划，不开任何 socket
    python scripts/attack_demo.py --workers 4 --port 18090
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, Callable

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from fin_logic_cyber_range.gateway import (  # noqa: E402
    HEALTH_PATH,
    LEDGER_PATH,
    SIGNATURE_HEADER,
    TRANSFER_PATH,
    MockGatewayServer,
)
from fin_logic_cyber_range.ledger import (  # noqa: E402
    ControlSet,
    Instruction,
    instruction_signature,
)
from fin_logic_cyber_range.oracle import RangeAssessment, assess  # noqa: E402
from fin_logic_cyber_range.runner import HttpResult, post_instruction  # noqa: E402
from fin_logic_cyber_range.safety import (  # noqa: E402
    BIND_HOST,
    LOCAL_HOSTS,
    container_bind_allowed,
    ensure_local_url,
    split_base_url,
)
from fin_logic_cyber_range.scenario import Scenario, Step  # noqa: E402
from fin_logic_risk import RiskLevel  # noqa: E402

REQUEST_TIMEOUT = 5.0
BARRIER_TIMEOUT = 5.0
DEFAULT_PORT = 18080
DEFAULT_SECURE_PORT = 18081
DEFAULT_WORKERS = 6
MAX_WORKERS = 8
DEFAULT_WINDOW_MS = 20
OUTPUT_PATH = _PROJECT_ROOT / "outputs" / "attack_demo.json"

BASELINE_ID = "INS-ATK-9901"
REPLAY_ID = "INS-ATK-9902"
RACE_ID = "INS-ATK-9903"
UNSIGNED_ID = "INS-ATK-9904"


def build_arg_parser() -> argparse.ArgumentParser:
    """The three knobs worth exposing: 端口、并发数、是否落盘。"""
    parser = argparse.ArgumentParser(
        prog="attack_demo",
        description=(
            "开一个本地靶场，然后对它模拟一次金融业务逻辑攻击"
            "（合成账户 / 仅回环 / 请求量写死）。"
        ),
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="vulnerable 臂端口")
    parser.add_argument(
        "--secure-port", type=int, default=DEFAULT_SECURE_PORT, help="secure 臂端口（对照）"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="并发重试风暴的线程数，2..%d（默认 %d）" % (MAX_WORKERS, DEFAULT_WORKERS),
    )
    parser.add_argument(
        "--window-ms",
        type=int,
        default=DEFAULT_WINDOW_MS,
        help="vulnerable 臂的竞争窗口，0..500（默认 %d）" % DEFAULT_WINDOW_MS,
    )
    parser.add_argument(
        "--no-write", action="store_true", help="不写 outputs/attack_demo.json（纯内存演示）"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="只打印攻击计划与边界自检，不开任何 socket"
    )
    return parser


def _get_json(base_url: str, path: str, *, timeout: float = REQUEST_TIMEOUT) -> dict[str, Any]:
    """GET one read route, through the same safety gate the POST path uses.

    ``runner`` 只有 POST，因为剧本只写不读；攻击者视角的第一步恰恰是读
    ``/mock/v1/ledger``（"我先看看这里面有多少钱"），所以这里补一个 15 行的 GET，
    并且**先过** :func:`~fin_logic_cyber_range.safety.ensure_local_url` 再建连接——
    演示脚本不允许成为边界上的例外。

    Raises:
        SafetyViolation: 当 ``base_url + path`` 不是本地 mock 时。
    """
    url = ensure_local_url(base_url.rstrip("/") + path)
    host, port = split_base_url(url)
    connection = HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    return json.loads(raw.decode("utf-8"))


def _body(instruction_id: str, amount: str) -> dict[str, Any]:
    """The JSON body one transfer carries (built by :class:`Instruction`, so it validates)."""
    return Instruction(instruction_id=instruction_id, amount=amount).to_payload()


def _signature(instruction_id: str, amount: str) -> str:
    """The signature a well-behaved client would attach."""
    return instruction_signature(instruction_id, amount)


def _fire_together(
    base_url: str,
    endpoint: str,
    body: dict[str, Any],
    *,
    signature: str,
    workers: int,
) -> list[HttpResult]:
    """Release ``workers`` identical requests at the same instant and collect them.

    Same shape as :func:`fin_logic_cyber_range.runner._fire_together` (which is
    private), reproduced here so the demo's 6 行并发逻辑是可见的、而不是"聪明"的：
    ``Barrier`` 保证每个线程都已经过了自己的准备阶段才一起发包，否则第一枪可能
    在最后一枪上膛前就打完了，所谓"并发"退化成顺序重放。
    """
    barrier = threading.Barrier(workers)
    collected: list[HttpResult | None] = [None] * workers

    def worker(index: int) -> None:
        try:
            barrier.wait(timeout=BARRIER_TIMEOUT)
        except threading.BrokenBarrierError:
            pass  # 慢一拍的兄弟不该让整轮白跑
        collected[index] = post_instruction(base_url, endpoint, body, signature=signature)

    threads = [
        threading.Thread(target=worker, args=(index,), name="attack-%02d" % index, daemon=True)
        for index in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=REQUEST_TIMEOUT * 2)
    return [item for item in collected if item is not None]


def _describe(result: HttpResult) -> str:
    """One line per response: 状态码 + 是否被接受 + 落了哪张分录。"""
    if result.status == 0:
        return "transport error: %s" % (result.error or "unknown")
    posted = result.payload.get("posting_id") or "-"
    receipt = result.payload.get("receipt_id") or "-"
    replayed = result.payload.get("replayed")
    error = result.payload.get("error") or "-"
    return "%3d accepted=%-5s posted=%-5s replayed=%-5s receipt=%-8s error=%s" % (
        result.status,
        result.accepted,
        posted,
        bool(replayed),
        receipt,
        error,
    )


def _demo_scenario(workers: int) -> Scenario:
    """The attack as a :class:`Scenario`, so :func:`assess` can score it unchanged.

    这份剧本不落盘到 ``data/cyber_range/scenarios/``：它是演示用的临时实验，四个
    指令号（``INS-ATK-99xx``）刻意与已交付的三个剧本区分开，免得有人把演示当成
    回归基线。断言值仍然走同一个阶梯（``expect_vulnerable`` / ``expect_secure``）。
    """
    return Scenario(
        name="attack_demo",
        title="演示：重放 + 并发重试风暴 + 无签名注入",
        description=(
            "演示脚本一次性打出三类业务逻辑攻击：同一指令超时重发、并发重试风暴、"
            "不带签名头的指令。三类都只依赖'网关没有校验'，不需要任何内存破坏技巧。"
        ),
        steps=(
            Step(instruction_id=BASELINE_ID, action="transfer", amount="10.00"),
            Step(instruction_id=REPLAY_ID, action="transfer", amount="20.00", repeat=3),
            Step(
                instruction_id=RACE_ID,
                action="concurrent_transfer",
                amount="50.00",
                workers=workers,
            ),
            Step(instruction_id=UNSIGNED_ID, action="unsigned_transfer", amount="30.00"),
        ),
        expect_vulnerable=RiskLevel.CRITICAL,
        expect_secure=RiskLevel.NONE,
    )


def _signal_counts(access: tuple[Any, ...]) -> dict[str, int]:
    """How many records raised each detection signal (the observability answer)."""
    counts: dict[str, int] = {}
    for record in access:
        for signal in record.signals():
            counts[signal] = counts.get(signal, 0) + 1
    return dict(sorted(counts.items()))


def _balances(snapshot: dict[str, Any]) -> str:
    """``ACC-SYNTH-0001=500.00  ACC-SYNTH-0002=500.00`` - 账本快照的一行摘要。"""
    return "  ".join(
        "%s=%s" % (name, value) for name, value in sorted(snapshot.get("balances", {}).items())
    )


def _duplicates(snapshot: dict[str, Any]) -> list[str]:
    """Instruction ids the ledger wrote twice - the T+1 reconciliation answer."""
    return list(snapshot.get("duplicated_instructions", []))


def _start_arm(
    controls: ControlSet, port: int, window_seconds: float
) -> tuple[MockGatewayServer, str]:
    """Bind one arm on ``port``, falling back to an OS-chosen port when it is taken.

    Returns:
        ``(server, note)``; ``note`` says whether the fallback happened, because a
        demo that silently moves port hides a stray listener from the operator.
    """
    try:
        server = MockGatewayServer(controls, window_seconds=window_seconds, port=port)
        note = "按计划端口 %d" % port
    except OSError as exc:
        server = MockGatewayServer(controls, window_seconds=window_seconds, port=0)
        note = "端口 %d 被占用（%s），改用系统分配" % (port, exc)
    server.start()
    return server, note


def _evidence(result: HttpResult) -> dict[str, Any]:
    """Flatten one exchange into the JSON the evidence file keeps."""
    return {
        "status": result.status,
        "accepted": result.accepted,
        "replayed": bool(result.payload.get("replayed")),
        "receipt_id": result.payload.get("receipt_id", ""),
        "posting_id": result.payload.get("posting_id", ""),
        "error": result.payload.get("error", "") or result.error,
    }


def _attack(
    server: MockGatewayServer,
    scenario: Scenario,
    *,
    workers: int,
    say: Callable[[str], None],
) -> tuple[dict[str, Any], RangeAssessment]:
    """Play the four attack phases against a live arm and score the result.

    Args:
        server: an arm that is already serving.
        scenario: the same attack expressed as a :class:`Scenario`, so the verdict
            comes from :func:`~fin_logic_cyber_range.oracle.assess` unchanged.
        workers: threads released together in the retry-storm phase.
        say: line sink (the demo's console).

    Returns:
        ``(evidence, assessment)`` - evidence is JSON-ready, assessment is the
        stage-10 verdict on this arm.
    """
    base_url = server.base_url
    phases: dict[str, list[dict[str, Any]]] = {}

    health = _get_json(base_url, HEALTH_PATH)
    before = _get_json(base_url, LEDGER_PATH)
    say("  [1] 侦察：先看看靶场里有什么（攻击者视角）")
    say("      health     : status=%s mode=%s" % (health.get("status"), health.get("mode")))
    say("      controls   : %s" % (", ".join(server.controls.enforced()) or "none"))
    say("      初始余额   : %s" % _balances(before))
    say("      初始分录   : %d 条" % len(before.get("postings", [])))
    phases["recon"] = [
        {"route": HEALTH_PATH, "answer": health},
        {"route": LEDGER_PATH, "answer": before},
    ]

    say("")
    say("  [2] 基线：一笔正常指令，证明正常路径本身是好的")
    result = post_instruction(
        base_url,
        TRANSFER_PATH,
        _body(BASELINE_ID, "10.00"),
        signature=_signature(BASELINE_ID, "10.00"),
    )
    say("      %s -> %s" % (BASELINE_ID, _describe(result)))
    phases["baseline"] = [_evidence(result)]

    say("")
    say("  [3] 攻击 A · 重放：同一指令 %s 连发 3 次（客户端超时重发）" % REPLAY_ID)
    replay_body = _body(REPLAY_ID, "20.00")
    replay_sig = _signature(REPLAY_ID, "20.00")
    replay = [
        post_instruction(base_url, TRANSFER_PATH, replay_body, signature=replay_sig)
        for _ in range(3)
    ]
    for index, item in enumerate(replay, start=1):
        say("      #%d %s" % (index, _describe(item)))
    phases["replay"] = [_evidence(item) for item in replay]

    say("")
    say("  [4] 攻击 B · 并发风暴：%d 个线程同时释放 %s（双击 / 网关重试）" % (workers, RACE_ID))
    clock = time.perf_counter()
    race = _fire_together(
        base_url,
        TRANSFER_PATH,
        _body(RACE_ID, "50.00"),
        signature=_signature(RACE_ID, "50.00"),
        workers=workers,
    )
    elapsed_ms = (time.perf_counter() - clock) * 1000.0
    posted = sum(1 for item in race if item.payload.get("posting_id"))
    say("      %d 个请求在 %.0f ms 内返回，其中落账 %d 笔" % (len(race), elapsed_ms, posted))
    for index, item in enumerate(race, start=1):
        say("      线程 #%d %s" % (index, _describe(item)))
    phases["race"] = [_evidence(item) for item in race]

    say("")
    say("  [5] 攻击 C · 无签名：不发 %s 头，直接提交 %s" % (SIGNATURE_HEADER, UNSIGNED_ID))
    unsigned = post_instruction(base_url, TRANSFER_PATH, _body(UNSIGNED_ID, "30.00"), signature="")
    say("      %s -> %s" % (UNSIGNED_ID, _describe(unsigned)))
    phases["unsigned"] = [_evidence(unsigned)]

    after = _get_json(base_url, LEDGER_PATH)
    say("")
    say("  [6] 攻击后对账：余额 %s" % _balances(after))
    say(
        "      分录 %d 条，重复指令 %s"
        % (len(after.get("postings", [])), _duplicates(after) or "无")
    )
    for posting in after.get("postings", []):
        say(
            "        %-8s %s -> %s  %s  (instruction %s, receipt %s)"
            % (
                posting["posting_id"],
                posting["debit_account"],
                posting["credit_account"],
                posting["amount"],
                posting["instruction_id"],
                posting["receipt_id"],
            )
        )

    assessment = assess(
        scenario,
        controls=server.controls,
        postings=server.ledger.postings,
        access=server.log.records,
    )
    say("")
    say("  [7] 判定（复用阶段 10 的 classify_logic_risk，没有第二套评分）")
    for line in assessment.lines():
        say(line)
    say("      检测信号   : %s" % _signal_text(server.log.records))

    evidence = {
        "base_url": base_url,
        "mode": server.mode,
        "controls": server.controls.to_dict(),
        "requests": sum(len(phases[name]) for name in ("baseline", "replay", "race", "unsigned")),
        "phases": phases,
        "ledger_after": after,
        "assessment": assessment.to_dict(),
    }
    return evidence, assessment


def _signal_text(access: tuple[Any, ...]) -> str:
    """``duplicate_posting×7, unsigned_accepted×1`` - 一行看出"会不会被发现"。"""
    counts = _signal_counts(access)
    if not counts:
        return "none"
    return ", ".join("%s x%d" % (name, count) for name, count in counts.items())


def _print_boundary(args: argparse.Namespace, *, workers: int) -> None:
    """Boundary self-check printed before any socket exists - what a reviewer reads first."""
    print("  [0] 边界自检")
    print("      目标白名单 : %s" % ", ".join(sorted(LOCAL_HOSTS)))
    bind_note = "已放宽到 0.0.0.0（仅容器）" if container_bind_allowed() else "未放宽"
    print("      绑定地址   : %s（%s）" % (BIND_HOST, bind_note))
    print("      子进程     : 无 shell / 无 subprocess / 无注册表 / 无服务 / 无计划任务")
    print("      磁盘写入   : %s" % ("无（--no-write）" if args.no_write else OUTPUT_PATH))
    print(
        "      请求预算   : %d 个 POST/臂（workers=%d + 5），不重试、不循环"
        % (workers + 5, workers)
    )


def _checks(
    evidence_v: dict[str, Any],
    verdict_v: RangeAssessment,
    evidence_s: dict[str, Any],
    verdict_s: RangeAssessment,
) -> list[tuple[str, bool]]:
    """What the demo asserts about itself - 全是可数的结构事实，不是观感。"""
    duplicates_v = sorted(_duplicates(evidence_v["ledger_after"]))
    duplicates_s = sorted(_duplicates(evidence_s["ledger_after"]))
    unsigned_v = sum(1 for item in evidence_v["phases"]["unsigned"] if item["accepted"])
    unsigned_s = sum(1 for item in evidence_s["phases"]["unsigned"] if item["accepted"])
    replays_s = sum(1 for item in evidence_s["phases"]["replay"] if item["replayed"])
    return [
        (
            "vulnerable 出现重复分录（%s）" % (",".join(duplicates_v) or "无"),
            duplicates_v == sorted([RACE_ID, REPLAY_ID]),
        ),
        ("vulnerable 接受无签名请求", unsigned_v == 1),
        ("vulnerable 判定 == 预期 critical", verdict_v.passed),
        ("secure 没有重复分录", duplicates_s == []),
        ("secure 拒绝无签名请求", unsigned_s == 0),
        ("secure 用回执挡住重放（2 次 replayed）", replays_s == 2),
        ("secure 判定 == 预期 none", verdict_s.passed),
    ]


def _comparison(
    evidence_v: dict[str, Any], evidence_s: dict[str, Any]
) -> list[tuple[str, str, str]]:
    """The 5-row table a reader screenshots: same attack, two arms."""

    def unsigned_accepted(evidence: dict[str, Any]) -> int:
        return sum(1 for item in evidence["phases"]["unsigned"] if item["accepted"])

    return [
        (
            "分录数",
            str(len(evidence_v["ledger_after"]["postings"])),
            str(len(evidence_s["ledger_after"]["postings"])),
        ),
        (
            "重复指令",
            ",".join(_duplicates(evidence_v["ledger_after"])) or "-",
            ",".join(_duplicates(evidence_s["ledger_after"])) or "-",
        ),
        ("无签名被接受", str(unsigned_accepted(evidence_v)), str(unsigned_accepted(evidence_s))),
        ("判定风险", evidence_v["assessment"]["risk"], evidence_s["assessment"]["risk"]),
        ("POST 请求数", str(evidence_v["requests"]), str(evidence_s["requests"])),
    ]


def main(argv: list[str] | None = None) -> int:
    """开靶场 → 打靶 → 判定 → 对照 → 落盘；返回进程退出码。"""
    args = build_arg_parser().parse_args(argv)
    if not 2 <= args.workers <= MAX_WORKERS:
        print("  --workers must be 2..%d, got %d" % (MAX_WORKERS, args.workers))
        return 2
    if not 0 <= args.window_ms <= 500:
        print("  --window-ms must be 0..500, got %d" % args.window_ms)
        return 2
    for name, value in (("port", args.port), ("secure-port", args.secure_port)):
        if not 1024 <= value <= 65535:
            print("  --%s must be 1024..65535, got %d" % (name, value))
            return 2

    scenario = _demo_scenario(args.workers)
    window = args.window_ms / 1000.0

    print("=" * 78)
    print("FIN LOGIC CYBER RANGE · 攻击演示（合成数据 / 仅回环 / 无持久化）")
    print("=" * 78)
    _print_boundary(args, workers=args.workers)
    print("")
    print("  攻击计划：")
    for step in scenario.steps:
        print("  " + step.line())
    if args.dry_run:
        print("")
        print("  --dry-run：计划已打印，未创建任何 socket。")
        return 0

    print("")
    print("-" * 78)
    print("  [开靶场] vulnerable 臂")
    print("-" * 78)
    vulnerable, note = _start_arm(ControlSet.vulnerable(), args.port, window)
    print("      监听地址   : %s（%s）" % (vulnerable.base_url, note))
    print("      缺失控制   : %s" % ", ".join(vulnerable.controls.missing()))
    try:
        evidence_v, verdict_v = _attack(vulnerable, scenario, workers=args.workers, say=print)
    finally:
        vulnerable.stop()

    time.sleep(0.2)
    print("")
    print("-" * 78)
    print("  [对照] 同一套攻击，打在 secure 臂上")
    print("-" * 78)
    secure, note = _start_arm(ControlSet.secure(), args.secure_port, window)
    print("      监听地址   : %s（%s）" % (secure.base_url, note))
    print("      生效控制   : %s" % ", ".join(secure.controls.enforced()))
    try:
        evidence_s, verdict_s = _attack(secure, scenario, workers=args.workers, say=print)
    finally:
        secure.stop()

    print("")
    print("=" * 78)
    print("  同一套攻击，两臂的结果")
    print("=" * 78)
    print("  %-18s %-22s %-22s" % ("指标", "vulnerable", "secure"))
    print("  " + "-" * 62)
    for name, left, right in _comparison(evidence_v, evidence_s):
        print("  %-18s %-22s %-22s" % (name, left, right))

    checks = _checks(evidence_v, verdict_v, evidence_s, verdict_s)
    print("")
    print("  自检：")
    for name, ok in checks:
        print("    [%s] %s" % ("OK" if ok else "!!", name))
    passed = all(ok for _, ok in checks)

    if not args.no_write:
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_by": "scripts/attack_demo.py",
            "scenario": scenario.to_dict(),
            "workers": args.workers,
            "window_ms": args.window_ms,
            "vulnerable": evidence_v,
            "secure": evidence_s,
            "checks": [{"name": name, "passed": ok} for name, ok in checks],
        }
        OUTPUT_PATH.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print("")
        print("  证据文件：%s" % OUTPUT_PATH)

    print("")
    print("-" * 78)
    print("  说明")
    print("    · 账户 ACC-SYNTH-*、金额与指令号全为合成数据，没有任何真实系统被访问；")
    print("    · 靶场是本进程内的 mock 网关，进程退出即消失，不留监听、不留数据；")
    print("    · 同一条攻击在 secure 臂上被 Idempotency_Token 与 Signature_Verification")
    print("      挡住，这正是动态验证静态推演的意义：结论可以被证伪。")
    print(
        "  结论：%s（%d/%d 自检通过）"
        % ("PASS" if passed else "FAIL", sum(1 for _, ok in checks if ok), len(checks))
    )
    return 0 if passed else 1


if __name__ == "__main__":  # pragma: no cover - entry point
    raise SystemExit(main())
