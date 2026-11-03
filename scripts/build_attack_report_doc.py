"""生成《金融业务逻辑靶场攻击模拟报告》Word 文档（.docx → .doc）。

用法::

    python scripts\\build_attack_report_doc.py
    python scripts\\build_attack_report_doc.py --out-dir "%USERPROFILE%\\Desktop"
    python scripts\\build_attack_report_doc.py --keep-docx   # 保留中间 docx

文档里的每一个数字都来自**已经跑过的两次真实运行**：

* ``outputs/cyber_range_report.md``（3 个剧本 × 2 个臂，6/6 一致，退出码 0）
* ``outputs/attack_demo.json`` + ``logs/_demo_run2.txt``（攻击演示，7/7 自检通过）

脚本本身只做排版：不联网、不读注册表、不调外部程序（除最后一步用 Word COM 另存为 .doc，
可用 ``--no-convert`` 跳过并只留 .docx）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT  # noqa: F401  (保留：横版表格时用)
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = Path.home() / "Desktop"
DOC_BASENAME = "金融业务逻辑靶场攻击模拟报告"

LATIN_FONT = "Times New Roman"
EAST_ASIA_FONT = "宋体"
HEADING_FONT = "微软雅黑"
CODE_FONT = "Consolas"

ACCENT = RGBColor(0x1F, 0x38, 0x64)  # 标题深蓝
MUTED = RGBColor(0x59, 0x59, 0x59)  # 说明灰
DANGER = RGBColor(0xB0, 0x1C, 0x1C)  # 风险红

BODY_PT = 10.5  # 五号
TABLE_PT = 8.5


def _style_font(
    style,
    *,
    latin: str,
    east_asia: str,
    size: float,
    bold: bool = False,
    color: RGBColor | None = None,
) -> None:
    """给一个段落/字符样式同时设定西文与中日韩字体（python-docx 只管西文）。"""
    font = style.font
    font.name = latin
    font.size = Pt(size)
    font.bold = bold
    if color is not None:
        font.color.rgb = color
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:ascii"), latin)
    rfonts.set(qn("w:hAnsi"), latin)
    rfonts.set(qn("w:eastAsia"), east_asia)


def build_styles(doc: Document) -> None:
    """把默认模板改成中文技术报告的版式（正文宋体、标题雅黑、代码 Consolas）。"""
    _style_font(doc.styles["Normal"], latin=LATIN_FONT, east_asia=EAST_ASIA_FONT, size=BODY_PT)
    normal = doc.styles["Normal"].paragraph_format
    normal.line_spacing = 1.45
    normal.space_after = Pt(4)

    for name, size, before, after in (
        ("Heading 1", 16, 18, 8),
        ("Heading 2", 13, 12, 5),
        ("Heading 3", 11.5, 9, 4),
    ):
        style = doc.styles[name]
        _style_font(
            style,
            latin=HEADING_FONT,
            east_asia=HEADING_FONT,
            size=size,
            bold=True,
            color=ACCENT,
        )
        fmt = style.paragraph_format
        fmt.space_before = Pt(before)
        fmt.space_after = Pt(after)
        fmt.keep_with_next = True
        fmt.line_spacing = 1.2

    code = doc.styles.add_style("RangeCode", WD_STYLE_TYPE.PARAGRAPH)
    _style_font(code, latin=CODE_FONT, east_asia=CODE_FONT, size=8.5)
    fmt = code.paragraph_format
    fmt.line_spacing = 1.0
    fmt.space_before = Pt(3)
    fmt.space_after = Pt(3)
    fmt.left_indent = Cm(0.35)
    fmt.keep_together = True

    caption = doc.styles.add_style("RangeCaption", WD_STYLE_TYPE.PARAGRAPH)
    _style_font(caption, latin=HEADING_FONT, east_asia=HEADING_FONT, size=8.5, color=MUTED)
    caption.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption.paragraph_format.space_before = Pt(2)
    caption.paragraph_format.space_after = Pt(10)


def _shade(element, fill: str) -> None:
    """给段落属性或表格单元格加底色（``w:shd``）。"""
    pr = element.get_or_add_pPr() if hasattr(element, "get_or_add_pPr") else element
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


def _cell_shade(cell, fill: str) -> None:
    _shade(cell._tc.get_or_add_tcPr(), fill)


def add_page_footer(section) -> None:
    """页脚：``第 N 页 / 共 M 页``，页码用域代码，Word 打开后自动更新。"""
    para = section.footer.paragraphs[0]
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = para.add_run("第 ")
    _style_font_of_run(run, size=8.5, color=MUTED)
    para._p.append(_field("PAGE"))
    run = para.add_run(" 页 / 共 ")
    _style_font_of_run(run, size=8.5, color=MUTED)
    para._p.append(_field("NUMPAGES"))
    run = para.add_run(" 页")
    _style_font_of_run(run, size=8.5, color=MUTED)


def _field(instr: str):
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), instr)
    run = OxmlElement("w:r")
    text = OxmlElement("w:t")
    text.text = "1"
    run.append(text)
    fld.append(run)
    return fld


def _set_east_asia(run, font_name: str) -> None:
    """给 run 设定中日韩字体；``rFonts`` 不存在时先建（schema 里它是 ``rPr`` 首个子元素）。"""
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    rfonts.set(qn("w:eastAsia"), font_name)


def _style_font_of_run(
    run, *, size: float, bold: bool = False, color: RGBColor | None = None
) -> None:
    run.font.name = LATIN_FONT
    run.font.size = Pt(size)
    run.font.bold = bold
    if color is not None:
        run.font.color.rgb = color
    _set_east_asia(run, EAST_ASIA_FONT)


def _add_rich_text(para, text: str) -> None:
    """把 ``**粗体**`` 与 ``` `等宽` ``` 标记解析成 run（报告里少量强调够用）。"""
    bold = False
    mono = False
    for chunk in _split_marks(text):
        if chunk == "**":
            bold = not bold
            continue
        if chunk == "`":
            mono = not mono
            continue
        if not chunk:
            continue
        run = para.add_run(chunk)
        if bold:
            run.font.bold = True
        if mono:
            run.font.name = CODE_FONT
            run.font.size = Pt(BODY_PT - 1.5)
            _set_east_asia(run, CODE_FONT)
        else:
            _set_east_asia(run, EAST_ASIA_FONT)


def _split_marks(text: str) -> list[str]:
    """按 ``**`` 与单个反引号切片，标记本身也作为独立片段返回，便于翻转状态。"""
    parts: list[str] = []
    buffer: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("**", i):
            if buffer:
                parts.append("".join(buffer))
                buffer = []
            parts.append("**")
            i += 2
            continue
        if text[i] == "`":
            if buffer:
                parts.append("".join(buffer))
                buffer = []
            parts.append("`")
            i += 1
            continue
        buffer.append(text[i])
        i += 1
    if buffer:
        parts.append("".join(buffer))
    return parts


def add_code_block(doc: Document, text: str, *, fill: str = "F4F6F8") -> None:
    """等宽代码块：整段一个段落，行间用软换行，保证底色连续。"""
    lines = text.rstrip("\n").split("\n")
    para = doc.add_paragraph(style="RangeCode")
    _shade(para._p.get_or_add_pPr(), fill)
    for index, line in enumerate(lines):
        if index:
            para.add_run().add_break()
        run = para.add_run(line if line else " ")
        run.font.name = CODE_FONT
        run.font.size = Pt(8.5)
        _set_east_asia(run, CODE_FONT)


def add_table(doc: Document, spec: dict) -> None:
    """渲染一张表：表头深蓝底白字、首列加粗、可选列宽与对齐。"""
    header = spec["header"]
    rows = spec["rows"]
    widths = spec.get("widths") or [16.0 / len(header)] * len(header)
    aligns = spec.get("aligns") or ["l"] * len(header)
    table = doc.add_table(rows=1, cols=len(header))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    head = table.rows[0]
    head_tr = head._tr
    tr_pr = head_tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:tblHeader"))  # 跨页重复表头
    for index, title in enumerate(header):
        cell = head.cells[index]
        cell.width = Cm(widths[index])
        _cell_shade(cell, "1F3864")
        para = cell.paragraphs[0]
        para.paragraph_format.space_after = Pt(1)
        para.paragraph_format.line_spacing = 1.0
        para.alignment = _alignment(aligns[index])
        run = para.add_run(title)
        run.font.bold = True
        run.font.size = Pt(TABLE_PT)
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.font.name = HEADING_FONT
        _set_east_asia(run, HEADING_FONT)

    for row_index, values in enumerate(rows):
        cells = table.add_row().cells
        for index, value in enumerate(values):
            cell = cells[index]
            cell.width = Cm(widths[index])
            if row_index % 2 == 1:
                _cell_shade(cell, "F2F5FA")
            para = cell.paragraphs[0]
            para.paragraph_format.space_after = Pt(1)
            para.paragraph_format.line_spacing = 1.0
            para.alignment = _alignment(aligns[index])
            _add_rich_text(para, str(value))
            for run in para.runs:
                run.font.size = Pt(TABLE_PT)
                if index == 0 and run.font.bold is None:
                    run.font.bold = True
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def _bottom_border(para, *, color: str = "1F3864", size: int = 8) -> None:
    ppr = para._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), str(size))
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), color)
    borders.append(bottom)
    ppr.append(borders)


def build_cover(doc: Document) -> None:
    """封面：标题、副标题、报告信息表。信息表只写真的（时间、环境、结论、数据性质）。"""
    for _ in range(3):
        doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = title.add_run("金融业务逻辑靶场攻击模拟报告")
    run.font.name = HEADING_FONT
    run.font.size = Pt(26)
    run.font.bold = True
    run.font.color.rgb = ACCENT
    _set_east_asia(run, HEADING_FONT)
    title.paragraph_format.space_after = Pt(6)

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = subtitle.add_run("在合成靶场中动态验证业务逻辑风险推演的准确性与可证伪性")
    run.font.name = HEADING_FONT
    run.font.size = Pt(12)
    run.font.color.rgb = MUTED
    _set_east_asia(run, HEADING_FONT)
    _bottom_border(subtitle)

    for _ in range(2):
        doc.add_paragraph()
    add_table(
        doc,
        {
            "header": ["项目", "内容"],
            "widths": [3.4, 12.6],
            "rows": [
                [
                    "报告对象",
                    "阶段 11 `fin_logic_cyber_range` 合成靶场 + `scripts/attack_demo.py` 攻击演示",
                ],
                ["测试接口", "`Transfer_API`（资金转账），合成流程 `Fund_Transfer_Process`"],
                [
                    "运行环境",
                    "Windows / Python 3.12.7 / 回环 `127.0.0.1:18080` 与 `:18081`，无容器、无外网",
                ],
                ["运行时间", "2026-11-02（两次运行：全量剧本 6/6；攻击演示 7/7 自检）"],
                ["核心结论", "推演出的 4 类后果全部在弱势臂复现；同一套攻击在防护臂被完全阻断"],
                [
                    "数据性质",
                    "账户 `ACC-SYNTH-*`、金额与指令号全为合成；不含任何真实客户或资金数据",
                ],
                ["安全性质", "仅回环、无子进程、无持久化、请求量写死；本机杀软全程无告警"],
            ],
        },
    )
    doc.add_page_break()


def _alignment(token: str):
    return {
        "l": WD_ALIGN_PARAGRAPH.LEFT,
        "c": WD_ALIGN_PARAGRAPH.CENTER,
        "r": WD_ALIGN_PARAGRAPH.RIGHT,
    }[token]


def render_blocks(doc: Document, blocks: list) -> None:
    """按声明式清单渲染整篇文档。"""
    for kind, payload in blocks:
        if kind == "h1":
            doc.add_heading(payload, level=1)
        elif kind == "h2":
            doc.add_heading(payload, level=2)
        elif kind == "h3":
            doc.add_heading(payload, level=3)
        elif kind == "p":
            _add_rich_text(doc.add_paragraph(), payload)
        elif kind == "note":
            para = doc.add_paragraph()
            para.paragraph_format.left_indent = Cm(0.4)
            _add_rich_text(para, payload)
            for run in para.runs:
                run.font.size = Pt(BODY_PT - 1)
                run.font.color.rgb = MUTED
        elif kind == "bullets":
            for item in payload:
                _add_rich_text(doc.add_paragraph(style="List Bullet"), item)
        elif kind == "numbers":
            for item in payload:
                _add_rich_text(doc.add_paragraph(style="List Number"), item)
        elif kind == "code":
            add_code_block(doc, payload)
        elif kind == "table":
            add_table(doc, payload)
        elif kind == "caption":
            para = doc.add_paragraph(style="RangeCaption")
            _add_rich_text(para, payload)
            for run in para.runs:  # 表注里的等宽片段也要服从注脚字号与灰色
                run.font.size = Pt(8.5)
                run.font.color.rgb = MUTED
        elif kind == "pagebreak":
            doc.add_page_break()
        elif kind == "spacer":
            doc.add_paragraph()
        else:  # pragma: no cover - 声明式清单写错时立刻炸，别静默丢内容
            raise ValueError("未知的内容块类型: %r" % (kind,))


# --------------------------------------------------------------------------- 正文
# 拼装策略：分块 extend，避免单次写入过大；顺序即文档顺序。

CONTENT: list = [
    ("h1", "1  摘要"),
    (
        "p",
        "本报告记录一次**完全本机、完全合成**的金融业务逻辑攻击模拟。靶场在回环地址上启动两个只差一道开关的 "
        "mock 网关：`vulnerable` 臂不校验幂等令牌、不校验请求签名；`secure` 臂补齐这两项控制，其余配置（端口之外"
        "的一切）完全相同。攻击者角色由 `scripts/attack_demo.py` 扮演，它按顺序做四件事——读账本、正常转账、"
        "重放同一笔指令、6 线程同时提交同一笔指令，最后再补一发不带签名的指令。",
    ),
    (
        "p",
        "结果是干净的二分：弱势臂写下 **11 条分录**，其中 `INS-ATK-9902` 被记了 3 次、`INS-ATK-9903` 被记了 6 次，"
        "余额从 1000.00 掉到 600.00；防护臂面对同一套攻击只写下 **3 条分录**，另外 7 次请求被回执机制挡回"
        "（`replayed=true`），1 次无签名请求被 401 拒绝，余额 920.00。判定侧复用阶段 10 的 `classify_logic_risk`，"
        "弱势臂 `observed=critical`、防护臂 `observed=none`，与本体预测逐一相符。",
    ),
    (
        "p",
        '这份报告想说的不是"造了一个靶场"，而是：**静态推演给出的可能性，可以被一次成本极低的动态实验证伪**。'
        '6 个（剧本 × 臂）组合里没有一处需要调参才能对上，也没有一处被"全绿"掩盖——过程中反而发现一条本体缺口'
        "（`Unsigned_Instruction_Accepted` 在基准图里没有条款边），这条缺口被写进报告，而不是被吞掉。",
    ),
    (
        "table",
        {
            "header": ["指标", "数值", "说明"],
            "widths": [3.8, 4.6, 7.6],
            "rows": [
                [
                    "剧本 × 臂 组合",
                    "6 / 6 一致",
                    "3 个剧本 × 2 个臂，判定与本体预测完全一致，CLI 退出码 0",
                ],
                [
                    "攻击演示请求量",
                    "22 个 POST（11 / 臂）",
                    "硬上限 `workers + 5`，不重试、不循环；本轮 6 线程",
                ],
                ["弱势臂后果", "11 条分录 / 2 个重复指令", "`ACC-SYNTH-0001`：1000.00 → 600.00"],
                [
                    "防护臂同一套攻击",
                    "3 条分录 / 0 个重复指令",
                    "1000.00 → 920.00；7 次 `replayed=true`，1 次 401",
                ],
                ["实测最高风险", "critical", "4 条 finding，覆盖 4 类后果"],
                [
                    "并发证据",
                    "6 线程 / 28 ms 内 6 条分录",
                    "分录号顺序与线程号不一致，说明是真并发而非排队",
                ],
                ["演示自检", "7 / 7 通过", '含"防护臂必须挡住"的反向断言'],
                ["质量门", "115 passed / 覆盖率 98%", "本域测试；全量 907 passed"],
            ],
        },
    ),
    ("caption", "表 1  本轮运行的关键数字（全部来自真实运行输出，不是估算）"),
    ("h1", "2  背景：静态推演需要一个能反驳它的对手"),
    (
        "p",
        '阶段 10 的 `classify_logic_risk` 从本体图里读出形如"`Transfer_API` 缺 `Idempotency_Token` → 可能'
        '`Duplicate_Debit`"的结论。这类结论的性质是**可能性陈述**：它说某种后果在逻辑上被允许发生，但没说它在'
        "给定实现里一定发生。工程上真正被追问的是另外三个问题：",
    ),
    (
        "bullets",
        [
            '**推演出的后果真的会发生吗？** 缺幂等控制，到底是"理论上可能重复"，还是"点两下就多扣一笔"？',
            "**补上控制真的挡得住吗？** 加了令牌之后，重复请求是被拒绝、被静默吞掉，还是照样落账只是返回 200？",
            "**有没有本体没建模、但实现里确实发生的后果？** 图谱的边由人工维护，漏一条边，推演就永远看不到它。",
        ],
    ),
    (
        "p",
        "靶场的定位因此很明确：它**不是扫描器，也不是渗透测试工具**，而是一台**实验装置**——把待验证的那条推演"
        '放进一个可控、可复现、可反证的环境里，让"实现了什么"与"推演说了什么"当场对账。所以它刻意做小：'
        "一个接口、两个控制、三个剧本，全部合成数据，全部回环。",
    ),
]

CONTENT += [
    ("h1", "3  靶场架构与安全边界"),
    ("h2", "3.1  组成"),
    (
        "table",
        {
            "header": ["模块", "职责", "关键约束"],
            "widths": [3.6, 6.8, 5.6],
            "rows": [
                [
                    "`gateway.py`",
                    "`MockGatewayServer`：起两个臂的 HTTP 网关",
                    "两臂只差一个 `ControlSet`；竞态窗口只放大弱势臂",
                ],
                [
                    "`ledger.py`",
                    "内存账本：受理、落分录、出回执",
                    "弱势臂**没有**唯一约束，重复就是真重复",
                ],
                ["`observability.py`", "逐请求观测记录与信号提取", "只观测，不参与判定"],
                ["`oracle.py`", "`assess()`：把观测交给阶段 10 打分", "不写第二套评分逻辑"],
                ["`scenario.py`", "剧本 JSON 校验与执行计划", "并发上界 32、重发上界 8，越界即拒"],
                [
                    "`runner.py`",
                    "`post_instruction()`：唯一的发包路径",
                    "每次请求前 `ensure_local_url()`",
                ],
                ["`safety.py`", "回环白名单与非回环拒绝", "公网地址直接抛 `SafetyViolation`"],
            ],
        },
    ),
    ("caption", "表 2  靶场的七个模块（演示脚本复用其中 5 个，没有第二套发包代码）"),
    ("h2", "3.2  安全边界（本轮运行的边界自检原文）"),
    ("p", "演示脚本在开任何 socket 之前，先把自己的边界打印出来。下面是这次运行的原样输出："),
    (
        "code",
        "目标白名单 : 127.0.0.1, ::1, localhost, mock-gateway, mock-secure-gateway\n"
        "绑定地址   : 127.0.0.1（未放宽）\n"
        "子进程     : 无 shell / 无 subprocess / 无注册表 / 无服务 / 无计划任务\n"
        "磁盘写入   : D:\\fin_logic_attack_range\\outputs\\attack_demo.json\n"
        "请求预算   : 11 个 POST/臂（workers=6 + 5），不重试、不循环",
    ),
    (
        "p",
        "这份自检不是注释，而是**每次运行都会执行并打印**的断言：白名单只认 5 个主机名；绑定地址不许放宽到 "
        "`0.0.0.0`（容器场景由镜像内环境变量显式开启，宿主侧再靠 compose 只发布到 `127.0.0.1`）；唯一的磁盘写入"
        '是一个 JSON，可用 `--no-write` 关掉；请求量由 `workers` 推导，不是循环发到"够为止"。',
    ),
    ("h2", "3.3  为什么本机杀软不会介入"),
    (
        "p",
        "本次运行期间，火绒（`HipsDaemon` / `HipsTray` / `wsctrlsvc`）与 Windows Defender（`MsMpEng`）同时在线，"
        "**全程无告警、无拦截，进程正常退出（退出码 0）**。这不是运气，而是设计上避开了杀软的五类判据：",
    ),
    (
        "bullets",
        [
            "**无可执行物**：只写 `.py` 与 `.json`，不落地 `.exe` / `.bat` / `.ps1`；"
            "无 `subprocess`、`os.system`、shell。",
            "**无持久化**：不碰注册表、服务、计划任务、启动项、`%TEMP%`；进程退出后不留监听、不留数据。",
            "**无外联**：目标恒为回环，`ensure_local_url()` 每次请求前检查，公网/域名/https 一律抛异常；只有 3 个已知路由，不做扫描。",
            "**无混淆**：源码全明文，无 `eval`、无 `base64` 载荷、无打包壳。",
            "**无流量异常**：请求量写死（`--workers ≤ 8`，单臂 `workers + 5` 个 POST），不重试、不遍历。",
        ],
    ),
    (
        "note",
        "若在其它机器上被误拦，正确做法是把 `python.exe` 与项目目录加入白名单，而不是关闭防护；"
        "只想看计划不动网络时用 `--dry-run`：它只打印边界自检与攻击计划，不创建任何 socket。",
    ),
]

CONTENT += [
    ("h1", "4  攻击方案"),
    ("h2", "4.1  威胁模型"),
    (
        "p",
        "模拟的攻击者**不具备**内存破坏、代码执行、服务器提权能力，也不需要这些。它只需要三件在真实金融场景里"
        "很常见的东西：一条合法的转账通道、能重复发送同一个请求的能力、能并发发送同一个请求的能力。正式假设如下：",
    ),
    (
        "bullets",
        [
            "**有能力**：构造/重放合法格式的业务指令；并发发送；省略或篡改签名头；读取网关公开的账本查询路由。",
            "**无能力**：读取服务端内存或密钥；写入账本文件；绕过网络边界访问非回环地址（由 `safety.py` 强制）。",
            "**收益模型**：让同一笔指令被多次记账（多扣付款方、多记收款方），或让未授权指令入账。",
            "**关键前提**：弱势臂不启用 `Idempotency_Token` 与 `Signature_Verification`——这正是本体推导出的两个缺失控制。",
        ],
    ),
    ("h2", "4.2  三个剧本"),
    (
        "table",
        {
            "header": ["剧本", "攻击动作", "请求数", "弱势臂预测", "现实对应"],
            "widths": [3.6, 5.0, 1.8, 2.4, 3.2],
            "aligns": ["l", "l", "c", "c", "l"],
            "rows": [
                [
                    "`replay_transfer`",
                    "同一笔转账指令原样重放两次",
                    "2",
                    "high",
                    "客户端超时重发、网关重试",
                ],
                [
                    "`concurrent_transfer`",
                    "8 个线程同刻提交同一指令",
                    "8",
                    "critical",
                    "用户双击、重试风暴",
                ],
                [
                    "`unsigned_transfer`",
                    "省略签名头提交转账",
                    "1",
                    "medium",
                    "中间人改包、内部调用绕过网关",
                ],
            ],
        },
    ),
    (
        "caption",
        '表 3  三个剧本与其对应的真实故障模式（"预测"一列来自阶段 10 的静态推演，不是跑完再填的）',
    ),
    (
        "p",
        "注意第三行的预测是 **medium 而不是 high/critical**：`Unsigned_Instruction_Accepted` 在本体图里没有条款边，"
        '只能落到"无条款"档。这个"偏低"不是 bug，而是图谱本身的缺口被如实反映出来（见第 6 章）。',
    ),
    ("h2", "4.3  攻击演示的七个阶段"),
    (
        "p",
        '上面的剧本是"跑完给结论"的批处理形态。演示脚本把它们拆成可见的七步，每步都留观测点，并且在同一个'
        "进程里对两个臂各跑一遍同一套动作：",
    ),
    (
        "table",
        {
            "header": ["阶段", "动作", "观测点"],
            "widths": [2.0, 7.6, 6.4],
            "rows": [
                [
                    "1 侦察",
                    "`GET /mock/v1/health`、`GET /mock/v1/ledger`",
                    "模式、生效控制、初始余额与分录数",
                ],
                [
                    "2 基线",
                    "`INS-ATK-9901` 转 10.00，带签名",
                    '正常路径本身是通的（排除"靶场坏了"的解释）',
                ],
                ["3 攻击 A", "`INS-ATK-9902` 转 20.00，顺序连发 3 次", "同一指令是否产生多条分录"],
                [
                    "4 攻击 B",
                    "`INS-ATK-9903` 转 50.00，6 线程同刻释放",
                    "并发窗口内是否各自独立落账",
                ],
                [
                    "5 攻击 C",
                    "`INS-ATK-9904` 转 30.00，不发签名头",
                    "网关是否校验签名（200 还是 401）",
                ],
                ["6 对账", "读账本快照", "余额、分录总数、重复指令集合"],
                [
                    "7 判定",
                    "`assess()` + `classify_logic_risk`",
                    "实测风险、finding、证据、自检结果",
                ],
            ],
        },
    ),
    ("caption", "表 4  演示脚本的七个阶段（两臂执行完全相同的动作，唯一变量是控制开关）"),
    (
        "p",
        "第 4 步的并发是**真的同时**：脚本用 `threading.Barrier` 让 6 个线程在同一个屏障上就绪，屏障一放就各自"
        '发请求；弱势臂的竞争窗口设为 20 ms，让"检查—落账"之间的间隙足以被穿透。这不是"循环发 6 次"——'
        "循环发 6 次的第 1 次就会在账本里留下痕迹，第 2 次起会被当作普通重复处理，测不出竞态。",
    ),
]

CONTENT += [
    ("h1", "5  实跑结果（一次真实运行）"),
    ("h2", "5.1  全量剧本：6 个组合全部与预测一致"),
    (
        "p",
        "先看批处理形态的结论。3 个剧本 × 2 个臂共 6 个组合，预测值在跑之前就由本体确定，跑完逐行比对，CLI 退出码 0：",
    ),
    (
        "table",
        {
            "header": ["剧本", "臂", "请求数", "实测风险", "预测风险", "判定"],
            "widths": [4.4, 2.6, 2.0, 2.6, 2.6, 1.8],
            "aligns": ["l", "l", "c", "c", "c", "c"],
            "rows": [
                ["`concurrent_transfer`", "vulnerable", "8", "**critical**", "critical", "PASS"],
                ["`concurrent_transfer`", "secure", "8", "**none**", "none", "PASS"],
                ["`replay_transfer`", "vulnerable", "2", "**high**", "high", "PASS"],
                ["`replay_transfer`", "secure", "2", "**none**", "none", "PASS"],
                ["`unsigned_transfer`", "vulnerable", "1", "**medium**", "medium", "PASS"],
                ["`unsigned_transfer`", "secure", "1", "**none**", "none", "PASS"],
            ],
        },
    ),
    ("caption", "表 5  全量运行结果（`outputs/cyber_range_report.md`，退出码 0）"),
    ("h2", "5.2  攻击演示：弱势臂的账本被写成什么样"),
    (
        "p",
        "然后是演示形态。下表每一步都是屏幕上真实打印过的行，钱数、分录号、回执号一一对应：",
    ),
    (
        "table",
        {
            "header": ["阶段", "请求", "响应", "账本变化"],
            "widths": [3.0, 5.4, 2.6, 5.0],
            "aligns": ["l", "l", "l", "l"],
            "rows": [
                ["2 基线", "`INS-ATK-9901` 10.00 ×1", "200", "新增 1 条：`PST-0001`"],
                [
                    "3 攻击 A",
                    "`INS-ATK-9902` 20.00 ×3（顺序）",
                    "200 ×3",
                    "新增 **3 条**：`PST-0002` / `0003` / `0004`",
                ],
                [
                    "4 攻击 B",
                    "`INS-ATK-9903` 50.00 ×6（并发）",
                    "200 ×6",
                    "新增 **6 条**：`PST-0005` … `0010`（28 ms 内）",
                ],
                [
                    "5 攻击 C",
                    "`INS-ATK-9904` 30.00 ×1（无签名）",
                    "200",
                    "新增 1 条：`PST-0011`，**受理并落账**",
                ],
            ],
        },
    ),
    ("caption", "表 6  弱势臂逐步账本变化：合计 11 条分录，余额 1000.00 → 600.00"),
    (
        "p",
        "第 4 步的分录号与线程号**不是同序**的。这次运行里线程 #1 拿到的分录号是 `PST-0007`、线程 #2 拿到 "
        "`PST-0005`、线程 #5 拿到 `PST-0006`——分录号由账本锁的获取顺序决定，谁先抢到锁谁先落账。演示脚本因此"
        '**按线程号原样打印、不做排序**：排序会让输出看起来"井然有序"，恰好掩盖了"这些请求真的同时到达"这一'
        "核心事实。",
    ),
    ("h2", "5.3  判定与证据"),
    (
        "p",
        "把观测交给 `assess()` 之后，弱势臂得到 `observed=critical`，4 条 finding 覆盖 4 类后果，"
        "并附 3 条可复算的证据（原样摘录）：",
    ),
    (
        "code",
        "检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Duplicate_Debit 风险，\n"
        "  违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。\n"
        "检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Race_Condition 风险，\n"
        "  违反 JR_T_0185_API_Spec，建议增加唯一请求 ID 校验。\n"
        "检测到 Transfer_API 缺失 Idempotency_Token，推导出存在 Replay_Attack 风险，\n"
        "  违反 Financial_Security_Level_3，建议增加唯一请求 ID 校验。\n"
        "检测到 Transfer_API 缺失 Signature_Verification，推导出存在 Unsigned_Instruction_Accepted\n"
        "  风险，违反 未映射的合规条款，建议补齐签名校验。\n"
        "\n"
        "证据：指令 INS-ATK-9902 产生 3 条分录：PST-0002 记 20.00（回执 RCP-0002）;\n"
        "      PST-0003 记 20.00（回执 RCP-0003）; PST-0004 记 20.00（回执 RCP-0004）\n"
        "证据：指令 INS-ATK-9903 产生 6 条分录：PST-0005 记 50.00（回执 RCP-0005）;\n"
        "      PST-0006 … PST-0010 各记 50.00（回执 RCP-0006 … RCP-0010）\n"
        "证据：请求 #11 未携带签名头仍被受理并落账",
    ),
    (
        "p",
        '判定链路上没有第二套评分：靶场的 `oracle.assess()` 只是把"缺哪些控制"和"观测到哪些后果"喂给阶段 10 的 '
        '`classify_logic_risk`。这也是为什么上表里"金额一致性"能被写进证据句——观测里同时有指令、分录与回执三者'
        "的对应关系，判定才有可复算的基础。",
    ),
]

CONTENT += [
    ("h2", "5.4  同一套攻击打在防护臂上"),
    (
        "p",
        "防护臂与弱势臂的唯一差别是 `ControlSet` 里多了 `Idempotency_Token` 与 `Signature_Verification`。"
        "脚本对两臂执行**完全相同**的 11 个请求，结果如下：",
    ),
    (
        "table",
        {
            "header": ["阶段", "请求", "响应", "账本变化"],
            "widths": [3.0, 5.4, 3.6, 4.0],
            "rows": [
                ["2 基线", "`INS-ATK-9901` 10.00 ×1", "200", "新增 1 条：`PST-0001`"],
                [
                    "3 攻击 A",
                    "`INS-ATK-9902` 20.00 ×3",
                    "200 ×3，其中 **2 次 `replayed=true`**",
                    "仅新增 1 条",
                ],
                [
                    "4 攻击 B",
                    "`INS-ATK-9903` 50.00 ×6",
                    "200 ×6，其中 **5 次 `replayed=true`**",
                    "仅新增 1 条",
                ],
                [
                    "5 攻击 C",
                    "`INS-ATK-9904` 30.00 ×1（无签名）",
                    "**401 `signature_rejected`**",
                    "无变化",
                ],
            ],
        },
    ),
    ("caption", "表 7  防护臂：11 个请求只落 3 条分录，7 次被回执挡回，1 次被签名校验拒绝"),
    (
        "p",
        '这里的关键不是"防护臂没出事"，而是**它出事的方式可被观测**：重复请求拿到的是 200 加 `replayed=true` '
        '与同一个回执号，而不是报错。这个区别在工程上很重要——超时重发的客户端应当收到"这笔已经成功过"的确定性'
        "答复，而不是一个 409 让它继续重试。",
    ),
    ("h2", "5.5  两臂对账"),
    (
        "table",
        {
            "header": ["指标", "vulnerable 臂", "secure 臂"],
            "widths": [4.6, 6.0, 5.4],
            "rows": [
                ["分录总数", "**11**", "**3**"],
                ["重复指令", "`INS-ATK-9902`、`INS-ATK-9903`", "无"],
                ["余额 `ACC-SYNTH-0001`", "600.00（少 400.00）", "920.00（少 80.00）"],
                ["余额 `ACC-SYNTH-0002`", "400.00（多 400.00）", "80.00（多 80.00）"],
                ["无签名请求", "受理并落账", "401 拒绝"],
                [
                    "观测信号",
                    "`duplicate_posting` ×9、`unsigned_accepted` ×1",
                    "`idempotent_replay` ×7、`rejected_request` ×1",
                ],
                ["判定（阶段 10 打分）", "**critical**", "**none**"],
            ],
        },
    ),
    ("caption", "表 8  两臂终态对比：同一套攻击，两种结局，账本差额 320.00 元（合成金额）"),
    (
        "p",
        "两臂余额差的 320.00 可以逐笔算清：弱势臂多扣了 2 笔 20.00（重放 2 次多余）与 5 笔 50.00（并发 5 次多余），"
        '再加 1 笔未授权的 30.00，合计 2×20 + 5×50 + 30 = 320.00。账能对平，说明"多扣的钱"不是估算，而是账本里'
        "真实存在的 8 条多余分录。",
    ),
]

CONTENT += [
    ("h2", "5.6  演示脚本的 7 条自检"),
    (
        "p",
        '演示结束前，脚本把"应该发生"与"实际发生"逐条比对。注意其中 4 条是**反向断言**——不是证明攻击成功，'
        "而是证明防护臂确实挡住了：",
    ),
    (
        "code",
        "[OK] vulnerable 出现重复分录（INS-ATK-9902,INS-ATK-9903）\n"
        "[OK] vulnerable 接受无签名请求\n"
        "[OK] vulnerable 判定 == 预期 critical\n"
        "[OK] secure 没有重复分录\n"
        "[OK] secure 拒绝无签名请求\n"
        "[OK] secure 用回执挡住重放（2 次 replayed）\n"
        "[OK] secure 判定 == 预期 none\n"
        "\n"
        "结论：PASS（7/7 自检通过）",
    ),
    (
        "p",
        '如果只断言"攻击成功了"，一个连正常路径都不通的坏靶场也能拿到 3/3——正常转账失败同样会"没有重复分录"。'
        '所以自检必须同时包含"弱势臂出事"和"防护臂没事"两组断言，并且要求基线请求先成功、防护臂的响应里必须'
        "出现 `replayed=true`（挡回重放）与 401（拒绝无签名）这两类可观测痕迹。",
    ),
    ("h1", "6  静态推演 vs 动态实测：两个方向的差集都有信息"),
    (
        "p",
        "把静态推演得到的（控制, 后果）集合与动态实测观测到的集合按集合做差，会得到两个方向，两个方向都有意义：",
    ),
    (
        "table",
        {
            "header": ["方向", "本轮结果", "含义"],
            "widths": [5.0, 5.0, 6.0],
            "rows": [
                ["静态有、动态未复现", "none", "本轮跑了全部剧本，静态推出的 3 条后果全部复现"],
                [
                    "动态有、本体未建模",
                    "`Signature_Verification/Unsigned_Instruction_Accepted`",
                    "本体缺边，靶场反过来给图谱报了缺口",
                ],
            ],
        },
    ),
    ("caption", "表 9  差集分析（`outputs/cyber_range_report.md` §3 的口径）"),
    ("h2", '6.1  方向一：只跑一个剧本时，"未复现"是必然的'),
    (
        "p",
        "静态推演针对的是 `Transfer_API` 整体，它给出的后果集合天然覆盖多个剧本。如果只跑 `replay_transfer`，"
        "观测里就不会出现 `Race_Condition`——这不是推演错了，而是实验没覆盖到。项目把这一条写成**断言**"
        '（"只跑单剧本时，未复现集合必须等于预期差集"），而不是允许它悄悄通过：一个只会输出"全部一致"的'
        "对账工具，等于没有对账。",
    ),
    ("h2", "6.2  方向二：靶场发现了本体没有的一条边"),
    (
        "p",
        "`unsigned_transfer` 让网关受理了不带签名头的指令，并落了账。这条后果在基准图里"
        "**只有入边没有出边**：`Signature_Verification` 有 `REQUIRES_CONTROL` 指向 "
        "`Transfer_API`，但没有 `LEADS_TO_VULNERABILITY` 连到 `Unsigned_Instruction_Accepted`。"
        '于是判定只能按"无条款"档计 `medium`，并在报告里单列一条**本体缺口**。',
    ),
    (
        "p",
        '这正是"动态验证"的额外价值：它不只检查推演对不对，还能指出推演**看不见什么**。回填建议已经写进'
        "`fin_logic_cyber_range/README.md` §6.2（补 `LEADS_TO_VULNERABILITY` 边与条款映射），补上之后这条"
        '后果的定级会从"无条款"升到应有的档位。',
    ),
    (
        "p",
        "顺带一个自证细节：本轮弱势臂的 finding 里，`Idempotency_Token` 一条控制扇出 3 类后果"
        "（`Duplicate_Debit` / `Race_Condition` / `Replay_Attack`），而 3 类后果的条款分别落在 "
        "`Financial_Security_Level_3`、`JR_T_0185_API_Spec`、`Financial_Security_Level_3`。条款不是随手写的常量，"
        '而是图谱里的边——这也是为什么"缺一条边"会直接影响定级。',
    ),
]

CONTENT += [
    ("h1", "7  观测与检测：把后果变成可数的信号"),
    (
        "p",
        '靶场不靠"看日志猜"来判断出事，而是把每一次交互压成结构化的观测记录，再从中提取数量有限、含义明确的'
        "信号。本轮出现的四个信号如下：",
    ),
    (
        "table",
        {
            "header": ["信号", "触发条件", "工程含义"],
            "widths": [3.8, 6.6, 5.6],
            "rows": [
                [
                    "`duplicate_posting`",
                    "同一 `instruction_id` 产生多条分录",
                    "**直接的资金损失信号**，可精确算出多扣多少",
                ],
                [
                    "`unsigned_accepted`",
                    "无签名头的请求返回 2xx 并落账",
                    "鉴权缺口，说明网关未做来源校验",
                ],
                [
                    "`idempotent_replay`",
                    "重复请求返回 2xx 且 `replayed=true`",
                    "控制生效的**正面**证据，不是错误",
                ],
                [
                    "`rejected_request`",
                    "请求返回 4xx（如 401 `signature_rejected`）",
                    '拒绝类观测，用于区分"挡住了"与"没人打"',
                ],
            ],
        },
    ),
    (
        "caption",
        "表 10  四个观测信号（弱势臂：`duplicate_posting` ×9、`unsigned_accepted` ×1；"
        "防护臂：`idempotent_replay` ×7、`rejected_request` ×1）",
    ),
    (
        "p",
        "这套信号可以平移到生产环境，作为 T+1 对账的规则集。本轮验证过的三条最值得先上：",
    ),
    (
        "numbers",
        [
            "**同指令多分录**：按业务流水号分组，`count(posting) > 1` 即告警——直接对应本轮的 9 次 `duplicate_posting`。",
            "**余额与流水不符**：账户余额变动与当日流水求和不等，说明中间有未记账或多记账的分录。",
            '**回执复用**：同一回执号被多次返回给"不同"请求（而不是同一请求的重发），意味着幂等键设计有问题。',
        ],
    ),
    (
        "p",
        '值得注意的是：**重复请求拿到 200 + `replayed=true` 不是异常**。真正该告警的是"同一指令落了多条分录"。'
        "把这两者混为一谈，会导致大量误报，最后运维把告警关掉。",
    ),
    ("h1", "8  防护建议"),
    (
        "table",
        {
            "header": ["优先级", "措施", "落地要点", "验证方式"],
            "widths": [1.8, 3.6, 6.4, 4.2],
            "aligns": ["c", "l", "l", "l"],
            "rows": [
                [
                    "P0",
                    "幂等令牌",
                    "客户端生成 `Idempotency-Key`；服务端落库时加唯一索引；命中重复直接返回首次回执",
                    "同一个 key 并发 N 次，账本只增 1 条且回执号相同",
                ],
                [
                    "P0",
                    "请求签名",
                    "对 `(method, path, body, timestamp, nonce)` 做 HMAC 或非对称签名；带时间窗与 nonce 去重",
                    "去掉签名头返回 401；改一个字节即验签失败",
                ],
                [
                    "P1",
                    "对账告警",
                    "按流水号分组统计分录数；余额变动与流水求和比对；异常进人工工单",
                    "用本轮的 11 条分录做回放，必须报出 2 个重复指令",
                ],
                [
                    "P1",
                    "网关去重与限速",
                    "对同一业务键做短窗口去重；对同一账户做速率限制",
                    "重试风暴下第 2..N 次请求被快速返回回执，而不是排队落账",
                ],
                [
                    "P2",
                    "审计留痕",
                    "把 `replayed=true`、`rejected_request` 一并写入审计流水",
                    '事后能回答"这次是挡住了，还是根本没人打"',
                ],
            ],
        },
    ),
    ("caption", "表 11  按投入产出排序的防护建议（P0 两项即本轮实验中被验证缺失的控制）"),
    (
        "p",
        "本轮实测给出的优先级依据很直接：加上 P0 两项之后，同一套攻击在防护臂上的资金损失从 320.00 降到 0，"
        "且客户端行为无需改变（重发依然返回 200，只是不再多扣钱）。P1 的两项是**兜底**——控制可能因为代码回滚、"
        '配置漂移而失效，对账是最后一道能发现"钱真的少了"的防线。',
    ),
]

CONTENT += [
    ("h1", '9  局限性与"这次没有证明什么"'),
    (
        "p",
        "一份诚实的技术报告必须写清边界。以下几点都是**主动声明**，不是遗漏：",
    ),
    (
        "bullets",
        [
            "**mock 网关不是真实系统**：它按业务逻辑风险的需要实现了受理、落账、回执，但没有真实的账户体系、清算、"
            '风控与数据库事务。本报告证明的是"这条推演链条自洽且可复现"，**不是**"某个真实系统存在漏洞"。',
            '**竞态窗口是被有意放大的**（本轮 20 ms）：这是实验设计，目的是让"检查—落账"的间隙可被稳定观测。'
            "真实系统的窗口宽度取决于实现，需要单独测量，不能拿这 20 ms 去估。",
            '**签名是演示用的**：靶场用截断 SHA-256 做签名校验，足以区分"有签名/无签名/签名错"，'
            "但**不是**生产可用的密码学方案（无密钥管理、无时间窗、无 nonce 去重）。",
            "**覆盖面很小**：只覆盖 2 个控制、1 个接口（`Transfer_API`）、3 个剧本。`Signature_Verification` 的"
            "其它后果（如 `Tampered_Instruction`）留待后续剧本。",
            "**演示的 GET 侦察是演示补的**：`runner.py` 只有 POST，读账本查询路由的 15 行代码由演示脚本自行实现，"
            "但它同样先过 `ensure_local_url()`——不是边界上的例外。",
            "**容器化未实跑**：`deploy/cyber_range/` 的 compose 配置已交付，但本机未安装 Docker，属"
            '"配置已交付、未在本机验证"。',
            "**数据全合成**：账户 `ACC-SYNTH-*`、金额 10/20/30/50、指令号 `INS-ATK-*` 均为构造值，"
            "不存在任何真实客户信息，也不涉及任何真实系统的访问。",
        ],
    ),
    ("h1", "10  复现方法"),
    ("h2", "10.1  命令"),
    (
        "code",
        "cd D:\\fin_logic_attack_range\n"
        "\n"
        "# 1) 全量剧本（3 剧本 × 2 臂），并写 JSON / Markdown\n"
        "python -m fin_logic_cyber_range `\n"
        "    --json outputs\\cyber_range_report.json --markdown outputs\\cyber_range_report.md\n"
        "\n"
        "# 2) 攻击演示：开靶场 + 七阶段攻击 + 两臂对照 + 判定\n"
        "python scripts\\attack_demo.py\n"
        "\n"
        "# 3) 只看计划，不开任何 socket\n"
        "python scripts\\attack_demo.py --dry-run\n"
        "\n"
        "# 4) 纯内存演示（不写证据文件），并把并发降到 4\n"
        "python scripts\\attack_demo.py --workers 4 --no-write\n"
        "\n"
        "# 5) 生成本报告\n"
        "python scripts\\build_attack_report_doc.py",
    ),
    ("h2", "10.2  退出码约定"),
    (
        "table",
        {
            "header": ["退出码", "含义"],
            "widths": [2.6, 13.4],
            "aligns": ["c", "l"],
            "rows": [
                ["0", "全部（剧本 × 臂）判定与预测一致；演示的 7 条自检全部通过"],
                ["1", "有组合与预测不一致，或自检失败（**这是需要人看的结论**，不是脚本 bug）"],
                ["2", "参数越界、剧本读不出来、端口非法、图表校验失败"],
            ],
        },
    ),
    ("caption", '表 12  退出码约定（非平稳/不一致不等于崩溃，退出码区分"结论"与"故障"）'),
    ("h2", "10.3  产物清单"),
    (
        "table",
        {
            "header": ["文件", "内容"],
            "widths": [7.0, 9.0],
            "rows": [
                ["`outputs\\cyber_range_report.md`", "全量剧本的逐臂结果、finding、证据、差集分析"],
                ["`outputs\\cyber_range_report.json`", "同上的机器可读版本"],
                [
                    "`outputs\\attack_demo.json`",
                    "演示证据：两臂响应、账本快照、两份 assessment、7 条自检",
                ],
                [
                    "`logs\\_demo_run2.txt`",
                    "本轮演示的完整终端输出（本报告引用的原文均出自此文件）",
                ],
                ["`fin_logic_cyber_range\\README.md`", "靶场设计论证与演示说明"],
            ],
        },
    ),
    ("caption", "表 13  本轮运行产生的文件（`outputs/` 与 `logs/` 已在 `.gitignore` 中）"),
    ("h1", "附录 A  术语与本体映射"),
    (
        "table",
        {
            "header": ["后果", "缺失控制", "违反条款", "现实含义"],
            "widths": [4.4, 4.0, 3.8, 3.8],
            "rows": [
                [
                    "`Duplicate_Debit`",
                    "`Idempotency_Token`",
                    "`Financial_Security_Level_3`",
                    "同一笔钱被扣两次",
                ],
                [
                    "`Race_Condition`",
                    "`Idempotency_Token`",
                    "`JR_T_0185_API_Spec`",
                    "并发下检查与落账不同步",
                ],
                [
                    "`Replay_Attack`",
                    "`Idempotency_Token`",
                    "`Financial_Security_Level_3`",
                    "旧请求被原样重放仍生效",
                ],
                [
                    "`Unsigned_Instruction_Accepted`",
                    "`Signature_Verification`",
                    "未映射（本体缺口）",
                    "伪造来源的指令被受理",
                ],
            ],
        },
    ),
    ("caption", "表 14  四类后果与本体图里的控制、条款对应关系"),
    ("h1", "附录 B  环境与质量门"),
    (
        "table",
        {
            "header": ["项目", "值"],
            "widths": [4.6, 11.4],
            "rows": [
                ["Python", "3.12.7（Anaconda）"],
                ["操作系统", "Windows（本机，回环运行）"],
                [
                    "运行期安全软件",
                    "火绒 `HipsDaemon` / `HipsTray` / `wsctrlsvc` + Defender `MsMpEng`，全程无告警",
                ],
                ["本域测试", "115 passed；覆盖率 98%（1663 语句 / 36 未覆盖）"],
                ["全量测试", "907 passed（框架 + 阶段 7–11）"],
                ["代码风格", "`black --line-length 100` + `flake8 --max-line-length=100`，0 告警"],
                ["依赖", "仅 Python 标准库（本报告生成脚本额外用 `python-docx` 与 Word COM）"],
            ],
        },
    ),
    ("caption", "表 15  运行环境与质量门"),
    ("spacer", None),
    (
        "note",
        "本报告由 scripts/build_attack_report_doc.py 依据上述两次运行的真实产物生成；文中所有金额、分录号、"
        "回执号、信号计数均可回溯到 outputs/attack_demo.json 与 logs/_demo_run2.txt。",
    ),
]


def build_document() -> Document:
    """组装整篇文档：A4、中文版式、页脚页码、封面、正文。"""
    doc = Document()
    build_styles(doc)
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(2.4)
    section.bottom_margin = Cm(2.2)
    section.left_margin = Cm(2.3)
    section.right_margin = Cm(2.3)
    add_page_footer(section)
    build_cover(doc)
    render_blocks(doc, CONTENT)
    return doc


def save_as_doc(docx_path: Path, doc_path: Path) -> int | None:
    """用 Word COM 把 .docx 另存为真正的 .doc（``wdFormatDocument`` = 0）。"""
    import win32com.client  # 延迟导入：没装 pywin32 时 --no-convert 仍可用

    word = win32com.client.DispatchEx("Word.Application")
    word.Visible = False
    word.DisplayAlerts = 0
    pages: int | None = None
    try:
        document = word.Documents.Open(str(docx_path), ReadOnly=False, AddToRecentFiles=False)
        try:
            try:
                pages = int(document.ComputeStatistics(2))  # wdStatisticPages
            except Exception:  # pragma: no cover - 统计失败不影响另存
                pages = None
            try:
                document.SaveAs2(str(doc_path), FileFormat=0)
            except AttributeError:  # Word 2007 没有 SaveAs2
                document.SaveAs(str(doc_path), FileFormat=0)
        finally:
            try:
                document.Close(SaveChanges=0)
            except Exception:  # pragma: no cover - 同下：关闭失败不影响已写出的文件
                pass
    finally:
        try:
            word.Quit()
        except Exception:  # pragma: no cover - 某些 COM 构建关闭后不再暴露 Quit
            pass
    return pages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_attack_report_doc",
        description="生成《金融业务逻辑靶场攻击模拟报告》(.docx → .doc)。",
    )
    parser.add_argument(
        "--out-dir", default=str(DEFAULT_OUT_DIR), help="成品 .doc 的目录（默认桌面）"
    )
    parser.add_argument(
        "--no-convert", action="store_true", help="只生成 .docx，不调用 Word 转 .doc"
    )
    args = parser.parse_args(argv)

    # 必须是绝对路径：Word/WPS 的 COM SaveAs 对相对路径会按**它自己**的当前目录解析，
    # 传相对路径会以"文档保存失败"收场（本机 WPS 实测）。
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    docx_path = _PROJECT_ROOT / "outputs" / (DOC_BASENAME + ".docx")
    docx_path.parent.mkdir(parents=True, exist_ok=True)

    build_document().save(str(docx_path))
    print("中间产物 (docx): %s  (%d 字节)" % (docx_path, docx_path.stat().st_size))

    if args.no_convert:
        target = out_dir / (DOC_BASENAME + ".docx")
        target.write_bytes(docx_path.read_bytes())
        print("成品 (docx): %s  (%d 字节)" % (target, target.stat().st_size))
        return 0

    target = out_dir / (DOC_BASENAME + ".doc")
    try:
        pages = save_as_doc(docx_path, target)
    except Exception as exc:  # Word 不可用 / COM 被拦
        print("转换失败：%s" % exc, file=sys.stderr)
        print("已保留 .docx：%s（可用 Word 手动另存为 .doc）" % docx_path, file=sys.stderr)
        return 1
    if not target.exists() or target.stat().st_size == 0:
        print("转换后文件缺失：%s" % target, file=sys.stderr)
        return 1
    print(
        "成品 (doc) : %s  (%d 字节, %s 页)"
        % (target, target.stat().st_size, pages if pages is not None else "未知")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
