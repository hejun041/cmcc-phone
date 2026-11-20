# 中国移动云手机 · 多用户长期保活与 Web 实时显示控制系统

纯原生 Node.js 20（零第三方编译依赖）打造的中国移动云手机多租户管理、长期信令连接保活与 WebRTC 实时显示触控控制平台。

## 核心能力

1. **官方手机验证码登录**：完整对接官方 H5 v6.6.8 协议栈（RSA-PKCS1 参数加密、交互式拼图滑块验证、短信验证码登录、`x-workkey` AES-128-GCM 响应自动解密），同时兼容密码登录与 Token 导入。
2. **7×24 小时原生长期连接保活**：
   - **云版底座（`platformType=1`）**：纯原生 Engine.IO v3 / Socket.IO WebSocket 信令网关长连接 + 自动心跳与实例活跃脉冲守护；
   - **T版底座（`platformType=2`）**：纯原生命令通道 WebSocket 长连接 + 15 秒双通道 `CMD_ACTION_HEART (100022)` 心跳守护；
   - **自动唤醒与断线重连**：休眠或回收态自动唤醒，网络波动指数退避重连，官方 Token 定时巡检与无感续期。
3. **多用户严格隔离**：
   - 首个注册用户自动成为管理员，支持多用户独立注册登录及管理员用户/配额管理；
   - 每个用户的移动账号、云手机列表、保活任务、Web 控制流及实时日志严格按 `ownerId` 隔离，敏感 Token 采用 `AES-256-GCM` 加密落盘。
4. **Web 实时画面显示与触控控制（防互踢无缝交接）**：
   - 内置云版 `CloudPhoneClient` 与 T版原生 WebRTC 播放器，支持高清视频流实时显示、鼠标/触屏滑动点击、三大金刚键（多任务 / 主页 / 返回）、文字同步、画质切换与 RTT 延迟显示；
   - 打开 Web 控制时自动通过租约机制暂停后台占线保活，退出 Web 控制后自动无缝恢复后台长期保活。

## 新增渠道：星辰超级智能体电脑（TeleAgent）

在移动云手机之外，内置了 **星辰超级智能体电脑**（agent.teleai.com.cn 云电脑）渠道，与移动账号共享同一套多租户隔离、日志与前端控制台。

### 能力

| 能力 | 说明 |
|---|---|
| 账号密码绑定 | 账号密码 + 服务端自动求解 AJ-Captcha 滑块，换取 `operationToken`（纯 Node 实现，无浏览器、无外部进程） |
| 一键续期 | 用已保存密码重新登录换新 Token（有效期约 29 天），失败会明确提示「用户名或密码不正确」 |
| 解绑 | 删除账号与其实例、停止对应巡检任务 |
| 进入控制 | `instance/connect` 换官方 `pc.ctyun.cn` 桌面入口，内嵌 iframe 打开 |
| 开机 / 重启 | `instance/start`、`instance/restart`（回收态下重启自动降级为开机） |
| 保活策略 | 可配巡检间隔（15s~24h）与「回收后自动开机」开关；巡检把实例状态写回前端 |

### 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/teleai/login` | `{loginName,password,remark}` 绑定并同步实例 |
| POST | `/api/teleai/accounts/:id/renew` | 一键续期 |
| POST | `/api/teleai/accounts/:id/sync` | 重新同步实例 |
| DELETE | `/api/teleai/accounts/:id` | 解绑 |
| POST | `/api/teleai/instances/:id/power` | `{action:"start"｜"restart"｜"cancel"}` |
| GET | `/api/teleai/instances/:id/desktop` | 获取桌面入口 URL |
| PATCH | `/api/teleai/instances/:id/settings` | `{keepaliveEnabled,autoStart,checkIntervalSec,name}` |

### 协议要点（实测）

- 登录：`www.teleai.com.cn` UPMS —— 密码用 `AES-128-GCM(裸密码串)`，key/iv 用 `RSA-OAEP-SHA256` 包裹，AAD 为 `loginName&keyId&timestamp&requestId&clientId`；`captchaCheckResult` 必须是对象 `{captchaVerification}`。
- 验证码：`AES-128-ECB(token + "---" + JSON({x,y:5}), secretKey)`；缺口求解在 `src/teleaiCaptcha.js`（自研 PNG 解码 + 轮廓匹配，实测 6/6）。
- 业务：`agent.teleai.com.cn/teleagent-manager/v1/instance/*`，Cookie 带 `operationToken`，404/401 统一映射为「登录失效」。

### 两级保活

| 级别 | 机制 | 作用 |
|---|---|---|
| 可用性保活（默认） | 定时 `instance/list` 巡检 + 回收态自动 `start` | 实例被回收后自动拉起，状态常驻 |
| 协议级保活（可选，按实例开关） | 复刻 CLINK：`instance/connect` → ctyun 协商 → `getConnectDataByToken` → WSS 三通道（MAIN/DISPLAY/INPUTS）→ 5s/30s 心跳 + 假鼠标 | 服务端视角就是「客户端正在使用」，才能真正压住空闲回收 |

- 协议级保活默认**关闭**，勾选后才会建立桌面长连接；关闭即断开，不会长期占着会话。
- 被踢保护：服务端关闭 MAIN / 认证被拒 / `CLIENT_OFFLINE` → 判定有人在用，默认等 `kickWaitSec`（1800s）再回来，避免把你手动打开的桌面顶掉。
- 假鼠标走 INPUTS 通道（`x,y,buttons,display_id` 11 字节），每 `moveSec` 秒在右下角画 20px 小方框、不点击；服务端 `MOUSE_MOTION_ACK` 回执可验证输入真的进了 guest。

### 实测（2026-11-19，真实账号 + 真实云电脑）

```
POST /api/teleai/instances/:id/clink {action:"start"}
  → [MAIN]    READY (auth ok), heartbeat 5000ms
  → [MAIN]    LOGIN_INFO sent, 395 bytes
  → [MAIN]    MAIN_INIT 鼠标模式=SERVER(相对) session=1671334340
  → [DISPLAY] READY (auth ok), heartbeat 30000ms
  → [INPUTS]  READY (auth ok), heartbeat 30000ms
60 秒采样：MAIN 心跳 10/10，DISPLAY/INPUTS 各 1，输入 4 条 / ACK 1
POST .../clink {action:"stop"} → 三通道干净关闭
```

### 已知边界

- 协议级保活依赖浏览器侧同款 TLS/WS 环境（`deskmsgz`/`jsyz...deskmgr` 网关），内网或断网环境连不上会进 error 并指数退避。
- 绑定/续期会真实产生一次官方登录，短时间内重复操作会累加失败计数，请勿用来试密码。

## 一键发布（NAS 部署）

```bash
sh scripts/sync-and-deploy.sh            # 自动打 tag：cmcc-phone:deploy-<时间戳>
sh scripts/sync-and-deploy.sh my-tag     # 指定镜像 tag
```

流程：`git fetch`（镜像优先，origin 兜底）→ `docker build` → 备份 compose 并切换镜像 →
`docker compose up -d` → 等待健康检查 → 打印容器状态与 `/api/health`。

可用 `SRC` / `APP` / `MIRROR` / `SERVICE` / `HEALTH_URL` 覆盖默认路径。国内直连
`github.com` 经常超时时，脚本会走 `MIRROR`（默认 `https://ghfast.top/`）。

## 启动方式

```bash
# 直接运行 (Node.js >= 20)
PORT=8680 node src/server.js

# 或使用 Docker Compose
docker compose up -d --build
```

## Docker 部署教程

### 方式一：拉取现成镜像（推荐）

镜像已发布到 Docker Hub：`lusean23/cmcc-phone:latest`（每次源码更新由 GitHub Actions 自动重新构建推送）。

```bash
docker run -d \
  --name cmcc-cloudphone-manager \
  --restart unless-stopped \
  -p 8680:8680 \
  -e TZ=Asia/Shanghai \
  -v cmcc-data:/app/data \
  lusean23/cmcc-phone:latest
```

启动后打开 `http://localhost:8680`，注册的第一个账号即为管理员。

### 方式二：Docker Compose（使用现成镜像）

```yaml
services:
  cmcc-cloudphone-manager:
    image: lusean23/cmcc-phone:latest
    container_name: cmcc-cloudphone-manager
    restart: unless-stopped
    ports:
      - "8680:8680"
    environment:
      - TZ=Asia/Shanghai
      - PORT=8680
      - DATA_DIR=/app/data
    volumes:
      - ./data:/app/data
```

```bash
docker compose up -d
```

### 数据持久化

- 所有账号、设备与令牌数据都存放在容器的 `/app/data` 目录（`DATA_DIR` 环境变量可改），务必挂载到宿主机目录或命名卷（如上例），否则重建容器会丢失数据。
- 升级镜像：`docker pull lusean23/cmcc-phone:latest` 后重建容器即可，数据卷不受影响。
