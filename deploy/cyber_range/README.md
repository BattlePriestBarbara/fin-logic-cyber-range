# deploy/cyber_range —— 可选的容器化部署（阶段 11）

这个目录**不是**运行靶场所必需的。日常验证用进程内 mock 就够：

```powershell
cd D:\fin_logic_attack_range
python -m fin_logic_cyber_range --mode both
```

容器化只在两种情况下有意义：想验证"两个臂通过 HTTP 跨进程互不干扰"，或者想把观测段接到一个
真实的日志管道上。**编写这份配置的机器上没有安装 Docker，所以它属于"配置已交付、未在本机实跑"
——第一次使用时请按下面的顺序自检。**

## 1. 起停

```bash
cd deploy/cyber_range
docker compose up --build -d                 # 构建 + 后台启动两个臂
docker compose ps                            # 两个服务都应是 healthy
curl -s http://127.0.0.1:18080/mock/v1/health   # vulnerable 臂
curl -s http://127.0.0.1:18081/mock/v1/health   # secure 臂
docker compose down -v                       # 清空（本来也只在内存里）
```

自检时至少要确认三件事：`health` 返回的 `mode` 分别是 `vulnerable` / `secure`；`18080` 与
`18081` 只监听在 `127.0.0.1`（`netstat -ano | findstr 18080` 应只见 `127.0.0.1:18080`）；
容器内 `curl http://<公网地址>` 应当失败（`internal: true`）。

## 2. 边界是怎么落地的

| 要求 | 落地位置 |
| --- | --- |
| 服务之间只在本 compose 网络内互通 | `networks.range.internal: true` |
| 宿主只暴露回环端口 | `ports: "127.0.0.1:18080:8080"`（**不要**改成 `"18080:8080"`） |
| 容器里能监听 0.0.0.0，但只在这个镜像里 | `Dockerfile` 的 `RANGE_ALLOW_CONTAINER_BIND=1`；`safety.ensure_bind_host()` 只认这一个开关 |
| 权限最小化 | `read_only`、`tmpfs: /tmp`、`cap_drop: [ALL]`、`no-new-privileges`、非 root `USER 10001` |
| 资源有界 | `mem_limit: 256m`、`pids_limit: 128` |
| 数据全合成 | 镜像里没有任何数据文件；账户由 `ledger.SYNTHETIC_ACCOUNTS` 在内存中创建 |

> 为什么容器里允许 `0.0.0.0`：Docker 的端口转发到不了容器自己的 loopback，绑定 `127.0.0.1` 的
> 进程无法被发布出去。这个许可由环境变量显式开启（默认关闭），宿主侧再靠 compose 把发布地址钉
> 在 `127.0.0.1`——两层各管一段，缺一层就不成立。

## 3. 把剧本打到容器上

`runner` 默认自己起服务，所以对容器跑剧本需要两步（本仓库当前只实现了第一步的命令行形态）：

1. 用 `--mode`/`--port` 起容器（见上）；
2. 用 `post_instruction()`（`fin_logic_cyber_range.runner`）对 `http://127.0.0.1:18080` 发请求。

`127.0.0.1` 与 `mock-gateway` / `mock-secure-gateway` 都在 `safety.LOCAL_HOSTS` 白名单里，所以
第 2 步不需要放宽任何限制。

## 4. 安全软件误报

镜像里只有 `python:3.12-slim` + `pydantic` + 本仓库的合成代码，没有网络工具、没有扫描器、没有
持久化。如果宿主侧的安全软件对"多线程 HTTP 客户端"报警，请把 `D:\fin_logic_attack_range` 与
`D:\Anaconda3\python.exe` 加入白名单，而不是关闭防护。
