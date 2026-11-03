# 合成金融业务逻辑靶场 —— mock 网关镜像（阶段 11）
#
# 镜像里只有本仓库的合成代码：没有真实 APK、没有真实 Manifest、没有真实账号或
# 卡号，也没有任何指向外部的配置项。运行它产生的唯一副作用是内存里的两条
# ACC-SYNTH-* 余额。
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    # 仅容器内允许绑定 0.0.0.0（Docker 端口转发到不了容器的 127.0.0.1）；
    # 宿主侧由 docker-compose 把发布端口限制在 127.0.0.1。
    RANGE_ALLOW_CONTAINER_BIND=1

WORKDIR /lab

# ontology_builder / fin_logic_risk 的唯一第三方依赖
RUN pip install --no-cache-dir "pydantic>=2,<3"

COPY ontology_builder ./ontology_builder
COPY fin_logic_risk ./fin_logic_risk
COPY fin_logic_cyber_range ./fin_logic_cyber_range

USER 10001:10001
EXPOSE 8080

# 默认跑 vulnerable 臂；secure 臂由 compose 用 --mode secure 覆盖。
CMD ["python", "-m", "fin_logic_cyber_range.serve", "--mode", "vulnerable", "--port", "8080"]
