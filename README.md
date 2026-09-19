# splitkey-vanity

Buyer-side tool for split-key vanity addresses — sell compute, not keys.
靓号 split-key 买家工具——卖家只卖算力，私钥不出你本机。

**Status**: v1.0.0 released. / 已发布 v1.0.0。

**Chains**: TRON first; the split-key protocol is pure secp256k1 and
extends to any chain (ETH, BTC) with a thin address-derivation adapter.
首发 TRON；split-key 内核是纯 secp256k1 数学，链差异只在地址推导
适配层，可扩展至 ETH/BTC。

## Trust model / 信任模型

**English**: With the split-key protocol, the seller only ever sees your
public key `B` and returns an offset `d`. Your final private key
`priv = b + d` is computed on your machine. The seller cannot derive it —
that is mathematics (EC discrete log), not a promise.

**中文**：Split-key 协议下，卖家只拿到你的公钥 `B`，返回偏移量 `d`。
最终私钥 `priv = b + d` 在你本机计算。卖家无法反推——这是椭圆曲线
离散对数难题的数学保证，不是口头承诺。

Orders are buyer-signed (`TRONSPK-ORDER-v1|pattern|B`) and bound to
payment by fingerprint `H = keccak256(order)` — the seller only starts
GPU work on escrow-released orders, and the escrow artifact is the
arbitration record.

订单由买家签名承诺，付款经托管绑定订单指纹 `H = keccak256(order)`——
卖家只对托管放行的订单开工，托管固化件即仲裁证据。

Anyone can audit this tool (single binary, minimal dependencies) or
re-implement the protocol from [`spec/`](spec/) — the specs are complete
enough to verify a delivery with any secp256k1 library.

任何人都可以审计本工具（单二进制、最小依赖），或按
[`spec/`](spec/) 用任意 secp256k1 库自行验证交付物。

## Install / 安装

Download a release artifact (linux tar.gz / windows zip) from
[Releases](../../releases), then verify it — 下载后先验证再使用：

```bash
sha256sum -c SHA256SUMS.txt            # checksum must match
tar xf tron-tool-v1.0.0-linux-x86_64.tar.gz
./tron-tool-v1.0.0-linux-x86_64/tron-tool --version   # → tron-tool 1.0.0
```

Release binaries are built by CI from the tagged commit — auditable
provenance, not a binary uploaded from the seller's machine.
Release 产物由 CI 从 tag commit 构建，来源可审计，而非卖家本机上传。

Or build from source: `cargo build --release`（stable Rust）。
也可源码构建：`cargo build --release`（stable Rust）。

## Quickstart / 快速上手

```bash
tron-tool keygen -o b.key                  # 生成买家秘密 b（0600），打印 B
tron-tool order --key b.key --pattern 'repeat:8' -o o.tronorder
                                           # 签订单 → .tronorder + 回显指纹 H
# … 付款托管 → 卖家跑 GPU → 收到 pkg.tronspk …
tron-tool redeem --package pkg.tronspk --key b.key \
    --expect-pattern 'repeat:8' --export-priv priv.key -o qr.png
                                           # 三段验收 → 导出私钥 + 收款 QR
tron-tool sign --key priv.key --message 'statement'      # TIP-191 声明签名
tron-tool verify --address T... --message 'statement' --signature 0x...
```

## Commands / 命令

The binary is `tron-tool`. All five commands implemented (v1.0.0)：
五命令均已实现（v1.0.0）：

| Command | Status | Purpose |
|---|---|---|
| `keygen -o <f>` | ✅ | 生成 (b, B)：b 落 0600 文件，B 打印供订单使用 |
| `order --key <f> --pattern 'repeat:<n>' -o <f>` | ✅ | 用 b 签订单承诺 → `.tronorder` + 回显 H（付款绑定引用） |
| `redeem --package <f> --key <f> --expect-pattern 'repeat:<n>'` | ✅ | 收货：验签 → 绑定/订单/自洽三检 → 导出私钥 + QR |
| `sign --key <f> --message <m>` | ✅ | 商户：TIP-191 签名收款地址声明 |
| `verify --address <a> --message <m> --signature <s>` | ✅ | 验证签名（恢复地址比对） |

The seller-side GPU generator and packaging tools are a separate,
private implementation — under split-key the seller's code has zero
trust requirements, so keeping it closed costs nothing and protects
the performance moat. Everything you need to verify a delivery is in
this repo + `spec/`.

卖家侧 GPU 生成器与打包工具为独立私有实现——split-key 下卖家侧
代码零信任需求，闭源不损信任只保性能护城河。验收交付所需的
全部逻辑在本仓 + `spec/`。

## Specs / 协议规范

- [`spec/split-key.md`](spec/split-key.md) — split-key 协议（B/d 格式、
  三段验收链、订单承诺与付款绑定、pattern 语法、Appendix B 测试向量）
- [`spec/package-format.md`](spec/package-format.md) — `TRONSPK1` 签名
  交付包格式与解析规则
- [`spec/message-signing.md`](spec/message-signing.md) — TIP-191 消息签名

## Security notes / 安全须知

- `b` 丢失 = 订单全损，工具生成后请备份（0600 文件）
- 验证只在离线工具内进行。任何要求"上传文件到网站验证"的都是钓鱼
- 付款前核对托管绑定的订单指纹 == 本机回显的 `H`，不符=订单被换
- All secrets are wiped from memory after use (zeroize); output files
  are `0600` and existing files are never overwritten.

## License

MIT OR Apache-2.0
