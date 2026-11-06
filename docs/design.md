# Pharos — 内网穿透开源产品设计

**日期**：2026-11-06  
**状态**：待老板审阅  
**公司**：维创盈通  
**授权**：t705u–t707u

## 1. 目标

做成熟开源内网穿透产品 **Pharos**（灯塔），不是一次性 MVP。

**首要场景**

1. 将内网本地服务暴露到公网（类 frp / ngrok）
2. SSH / 远程桌面等 TCP 反向隧道

**非目标（首版不做）**

- WireGuard / Tailscale 级 mesh VPN
- 兼容 frp 线协议
- 托管 SaaS 控制台（协议与自建 server 先行）

## 2. 已拍板决策

| 项 | 决定 |
|---|---|
| 定位 | 吸取 frp / rathole / CF Tunnel 优点后自研 |
| 语言 | Rust（工期不计，偏长期安全与并发边界） |
| 交付 | 单仓 workspace，**两二进制**：`pharos-server` / `pharos-client` |
| 流量 | TCP 反向优先，HTTP/HTTPS 子域紧随 |
| 鉴权 | PSK token 首版，可升 mTLS |
| 传输 | QUIC 默认，可降级 TLS over TCP |
| 配置 | TOML；热重载 |
| 许可证 | **Apache-2.0** |
| EKS | 同步沉淀楼层 / 决策矩阵 / loci（EKS 现无穿透专题） |

## 3. 架构

```
[本地服务 :port] <--TCP--> [pharos-client] <==控制+数据==> [pharos-server] <--公网--> [用户/SSH/浏览器]
```

- **控制面**：鉴权、注册隧道、心跳、映射热更新；帧带协议版本。
- **数据面**：多路复用（QUIC stream；TLS 降级时用自研多路）；TCP 透传；HTTP 按 Host 路由。
- **安全**：token；server ACL（允许的端口/子域）；审计日志；禁止默认无鉴权监听。
- **观测**：结构化日志；可选 metrics 钩子（Prometheus 文本或等价）。

## 4. 组件与接口

### 4.1 `pharos-server`

- 监听控制口与公网数据口（可同端口复用，实现自决）
- 校验 token，下发隧道 ID
- TCP 端口映射与 HTTP 虚拟主机
- ACL、限流钩子（首版可简单并发上限）

### 4.2 `pharos-client`

- 读 TOML：server 地址、token、本地映射列表
- 维持控制连接；按映射建立数据流
- 支持 `tcp` 与 `http` 映射类型
- 优雅重连与退避

### 4.3 配置示例（示意）

```toml
# client
server = "pharos.example.com:443"
token = "..."
[[tunnels]]
name = "ssh"
type = "tcp"
local = "127.0.0.1:22"
remote_port = 2222

[[tunnels]]
name = "web"
type = "http"
local = "127.0.0.1:3000"
hostname = "demo.pharos.example.com"
```

## 5. 协议原则

- 自研、文档公开帧格式；**不**兼容 frp。
- 版本协商；未知帧可忽略或拒绝（按安全策略）。
- 控制消息与数据流严格分离。

## 6. 质量与发布

- `cargo test` + 集成测（本机 server+client 环回）
- CI：linux/mac/windows 交叉构建与 release 资产
- README：快速开始、安全警告、与 frp/rathole/CF 对比表
- 语义化版本；CHANGELOG

## 7. EKS 沉淀（随首版 tag）

建议篇目：

1. `pharos-tunnel-delivery-stack-floor`
2. `pharos-tunnel-decision-matrix`（自研 vs frp vs CF vs mesh）
3. `pharos-tunnel-company-loci` / `pharos-tunnel-oss-github-loci`
4. Portal / stack-backend 挂接

## 8. 成功标准（首个可发布版本）

1. 两二进制可在本机完成 TCP 反向（含 SSH）与至少一种 HTTP Host 转发
2. 无 token 无法建立隧道
3. Apache-2.0 LICENSE + 协议文档草稿
4. EKS 楼层与 INDEX/tag 齐
5. 公开 Origin（或后续镜像 GitHub）仓库可克隆构建

## 9. 后续演进（不阻塞首版）

- mTLS、更细 ACL、带宽配额
- 官方托管入口（可选）
- GUI / 桌面壳封装（另立项）
