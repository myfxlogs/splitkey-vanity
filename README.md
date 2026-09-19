# tron-tool

Buyer-side tool for split-key TRON vanity addresses.
靓号买家工具：私钥在你自己电脑上生成，卖家数学上不可能知道。

## Trust model / 信任模型

**English**: With the split-key protocol, the seller only ever sees your
public key `B` and returns an offset `d`. Your final private key
`priv = b + d` is computed on your machine. The seller cannot derive it —
that is mathematics (EC discrete log), not a promise.

**中文**：Split-key 协议下，卖家只拿到你的公钥 `B`，返回偏移量 `d`。
最终私钥 `priv = b + d` 在你本机计算。卖家无法反推——这是椭圆曲线
离散对数难题的数学保证，不是口头承诺。

Anyone can audit this tool (single binary, minimal dependencies) or
re-implement the protocol from [`spec/`](spec/) — the specs are complete
enough to verify a delivery with any secp256k1 library.

任何人都可以审计本工具（单二进制、最小依赖），或按
[`spec/`](spec/) 用任意 secp256k1 库自行验证交付物。

## Modes / 模式

```
tron-tool keygen              # 生成 (b, B)：b 保密保存
tron-tool order               # 用 b 签订单承诺 → 提交 {订单,签名} 给卖家
tron-tool redeem              # 收货：验签 → 绑定/订单/模式三检 → 出私钥QR
tron-tool sign                # 商户：TIP-191 签名收款地址声明
tron-tool verify              # 验证签名（恢复地址比对）
```

## Specs / 协议规范

- [`spec/split-key.md`](spec/split-key.md) — split-key 协议（B/d 格式、验证公式）
- [`spec/package-format.md`](spec/package-format.md) — `TRONSPK1` 签名交付包格式
- [`spec/message-signing.md`](spec/message-signing.md) — TIP-191 消息签名

## Security notes / 安全须知

- `b` 丢失 = 订单全损，工具生成后请备份（0600 文件）
- 验证只在离线工具内进行。任何要求"上传文件到网站验证"的都是钓鱼
- 收款方付款前：扫码 + 数满尾号位数；不要从转账记录复制地址
- All secrets are wiped from memory after use (zeroize); output files are `0600`.

## License

MIT OR Apache-2.0
