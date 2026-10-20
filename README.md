# trojan-grpc-simple

这是从本目录 `trojan-rs` 的 gRPC 实现提炼出的 Python 精简服务端。它实现与 v2ray/Xray Trojan gRPC 兼容的核心路径：HTTP/2、`Hunk { bytes data = 1; }` gRPC 消息、Trojan `CONNECT` 和 TCP 双向转发。

不包含 UDP、WebSocket、ACME、回落站点、DNS 缓存及生产级限流；默认监听回环地址，适合作为协议学习、互操作验证或受控环境中的轻量服务。

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

## 设计范围与安全提示

- 仅支持 Trojan `CONNECT` (`0x01`)；收到 UDP Associate (`0x03`) 会返回 gRPC `INVALID_ARGUMENT`。
- 仅支持未压缩的 gRPC Hunk 帧，并默认将单条 Hunk 限为 16 KiB。
- 每个 HTTP/2 stream 是一个独立 TCP 隧道；服务端对密码使用 `SHA-224` 小写十六进制格式，与 `trojan-rs` 一致。
- 这是代理服务。请设置强密码、使用 TLS、限制网络访问，并仅在你授权的网络中部署。

## 验证

```bash
cd /Users/willoong/Desktop/trojan/trojan-python
python3 -m unittest discover -s tests -v
```
