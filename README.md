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

Download a release artifact from [Releases](../../releases),
then verify it — 下载后先验证再使用：

| Platform | Artifact |
|---|---|
| Linux x86_64 | `tron-tool-v*-linux-x86_64.tar.gz` |
| Linux aarch64 | `tron-tool-v*-linux-aarch64.tar.gz` |
| Windows x86_64 | `tron-tool-v*-windows-x86_64.zip` |
| macOS Intel | `tron-tool-v*-macos-x86_64.tar.gz` |
| macOS Apple Silicon | `tron-tool-v*-macos-arm64.tar.gz` |

```bash
sha256sum -c SHA256SUMS.txt            # checksum must match
tar xf tron-tool-v1.0.2-linux-x86_64.tar.gz
./tron-tool-v1.0.2-linux-x86_64/tron-tool --version   # → tron-tool 1.0.2
```

macOS Gatekeeper may flag the unsigned binary — allow it via
`xattr -d com.apple.quarantine tron-tool` or System Settings →
Privacy & Security. macOS 可能拦截未签名二进制，按此放行。

Release binaries are built by CI from the tagged commit — auditable
provenance, not a binary uploaded from the seller's machine.
Release 产物由 CI 从 tag commit 构建，来源可审计，而非卖家本机上传。

Or build from source: `cargo build --release`（stable Rust）。
也可源码构建：`cargo build --release`（stable Rust）。

## Quickstart / 快速上手

Run `tron-tool` with no arguments for the guided interactive menu —
启动先选语言（1=English / 2=中文），再进同级菜单：new order（下单，
仅此路径问 pattern）/ keygen（仅生成密钥）/ redeem（验收取件）。
下单路径内文件名按定制自动生成（`b-repeat6.key` / `repeat6.tronorder`），
完成一步自动回菜单并预选下一步，无需记参数：

```bash
tron-tool                # 交互菜单（En/中）：new order / keygen / redeem / sign / verify
```

Pattern 语法（§3.1）：`repeat:<n>` 尾号 n 位相同（裸数字 `8` 亦可）、
`pair:<k>` 对子连排（`pair:2`=AABB、`pair:3`=AABBCC）、`alt:2` 间隔对
（ABAB）、`suffix:<s>` 指定后缀字面（如 `suffix:8888`，2~8 位 base58
字符）。命中概率即成本：`pair:2`/`alt:2` 最易（≈1/3,423），
`suffix:8888` 最难（1/58⁴ ≈ repeat:5 的算力）。

**竞拍单 / auction wins（v1.2.0+）**：拍到靓号后卖家发 grant 凭证
（`TG1.…`，含 pattern+价格+单次 nonce，由卖家离线密钥签名）。下单时
粘贴——new order 菜单首问 grant 码，验签后免输 pattern；或
`tron-tool order -k b.key -p 'suffix:8888' --grant "TG1.…"` 生成 v2 订单。
工具本地验签+比对 pattern+查有效期，三项不符拒单。

Or scripted use — 脚本用法（`-k` key、`-p` pattern/package、`-o` out；
`-p`/`-e` 接受 §3.1 全语法或裸数字 `8`）：

```bash
tron-tool keygen -o b.key                  # 生成买家秘密 b（0600），打印 B
tron-tool order -k b.key -p 'repeat:8' -o o.tronorder
                                           # 签订单 → .tronorder + 回显指纹 H
# … 付款托管 → 卖家跑 GPU → 收到 pkg.tronspk …
tron-tool redeem -p pkg.tronspk -k b.key \
    -e 'repeat:8' --export-priv priv.key -o qr.png
                                           # 三段验收 → 导出私钥 + 收款 QR
tron-tool sign -k priv.key -m 'statement'            # TIP-191 声明签名
tron-tool verify -a T... -m 'statement' -s 0x...
```

### Offline generation / 离线生成（可选加固）

`b` never leaves your machine under the protocol — offline generation is
extra hardening, not a requirement. 协议下 b 本就不出机，离线是可选加固：

- `keygen --require-offline` — refuse when a network route is detected.
  Best-effort self-check only: it CANNOT prove a machine is offline
  (hotspots / VM bridges / compromised hosts evade it).
  检测到网络路由即拒绝生成；这是自检纪律工具，不是安全保证。
- Air-gapped flow / 气隙流程：offline machine runs `keygen` + `order` →
  move only the `.tronorder` (public-safe) to an online machine → upload →
  download `.tronspk` back to the offline machine → `redeem` offline.
  离线机生成并签名，仅 .tronorder 经联网机上传；交付包回离线机验收。

Keep your `.tronorder` safe — it is the pickup ticket: anyone holding it
(or H) can track the order and download the package (useless without `b`,
but it leaks your order).
妥善保管 `.tronorder`：它是取货凭证，持文件者可查单、下载交付包。

## Commands / 命令

The binary is `tron-tool`. Bare invocation opens the interactive menu
(v1.0.2+); all five commands also take arguments for scripted use：
裸跑进交互菜单；五命令均可参数化：

| Command | Status | Purpose |
|---|---|---|
| *(no args)* | ✅ | 交互菜单 guided menu |
| `keygen -o <f> [--require-offline]` | ✅ | 生成 (b, B)：b 落 0600 文件，B 打印供订单使用 |
| `order -k <f> -p 'repeat:<n>' -o <f> [--grant TG1.…]` | ✅ | 用 b 签订单承诺 → `.tronorder` + 回显 H（付款绑定引用）；`--grant` 出 v2 竞罚单 |
| `redeem -p <f> -k <f> -e 'repeat:<n>'` | ✅ | 收货：验签 → 绑定/订单/自洽三检 → 导出私钥 + QR |
| `sign -k <f> -m <m>` | ✅ | 商户：TIP-191 签名收款地址声明 |
| `verify -a <a> -m <m> -s <s>` | ✅ | 验证签名（恢复地址比对） |
| `inspect -f <f>` | ✅ | 查看 `.tronorder`：pattern/B/H + 签名校验（忘了定制要求用它） |

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
