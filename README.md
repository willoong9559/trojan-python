# trojan-grpc-simple

这是从本目录 `trojan-rs` 的 gRPC 实现提炼出的 Python 精简服务端。它实现与 v2ray/Xray Trojan gRPC 兼容的核心路径：HTTP/2、`Hunk { bytes data = 1; }` gRPC 消息、Trojan `CONNECT`、`UDP ASSOCIATE` 和双向转发。

不包含 WebSocket、ACME、回落站点、DNS 缓存及生产级限流；默认监听回环地址，适合作为协议学习、互操作验证或受控环境中的轻量服务。

## 安装与运行

```bash
cd /Users/willoong/Desktop/trojan/trojan-python
python3 -m venv .venv
.venv/bin/pip install -e .

# h2c，适合本机测试或由可信反向代理终止 TLS 的场景
.venv/bin/trojan-grpc-server --password 'change-me' --port 18443 --service-name GunService

# TLS + ALPN h2，供标准 gRPC 客户端直连
.venv/bin/trojan-grpc-server \
  --password 'change-me' --host 0.0.0.0 --port 443 \
  --service-name GunService --cert /path/to/fullchain.pem --key /path/to/privkey.pem
```

客户端访问路径为 `/GunService/Tun`。省略 `--service-name` 时，服务端接受任意以 `/Tun` 结尾的服务路径，兼容 Rust 项目的默认行为。

## Linux 一键部署（acme.sh）

脚本会从本仓库安装服务到 `/opt/trojan-python`，创建非登录 `trojan` 用户、systemd 服务及权限受限的证书/密码文件；再使用 acme.sh standalone HTTP-01 为域名申请 Let's Encrypt ECDSA 证书。续期后 acme.sh 会重启服务以加载新证书。

运行前，域名 A/AAAA 记录必须已指向服务器，公网 TCP `80` 和 `443` 必须可达，且 TCP `80` 没有被其他进程占用。云厂商的安全组不由脚本控制。支持 Debian/Ubuntu、RHEL/Fedora/Rocky/AlmaLinux、openSUSE 和 Arch；需要 systemd。

```bash
curl -fsSLO https://raw.githubusercontent.com/willoong9559/trojan-python/main/scripts/install_acme.sh
chmod +x install_acme.sh
sudo ./install_acme.sh \
  --domain tunnel.example.com \
  --email admin@example.com \
  --service-name GunService
```

省略 `--password` 后会安全地交互输入密码，避免把密码记录在 shell history 或进程参数中。默认启用 UDP；需要关闭可加 `--disable-udp`。脚本会检测活跃的 UFW 或 firewalld 并放行 TCP 80/443；不希望改动主机防火墙可加 `--skip-firewall`。

## 设计范围与安全提示

- 支持 Trojan `CONNECT` (`0x01`) 与 `UDP ASSOCIATE` (`0x03`)。UDP 使用 Trojan 的 UDP-over-TCP 数据帧；每个 gRPC stream 维护独立的 UDP association，默认 60 秒无流量关闭。可用 `--disable-udp` 禁用。
- 仅支持未压缩的 gRPC Hunk 帧，并默认将单条 Hunk 限为 16 KiB。
- 每个 HTTP/2 stream 是一个独立 TCP 或 UDP 隧道；服务端对密码使用 `SHA-224` 小写十六进制格式，与 `trojan-rs` 一致。
- 这是代理服务。请设置强密码、使用 TLS、限制网络访问，并仅在你授权的网络中部署。

## 验证

```bash
cd /Users/willoong/Desktop/trojan/trojan-python
python3 -m unittest discover -s tests -v
```
