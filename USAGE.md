# tron-tool 使用说明 · Quick Guide

Split-key 靓号买家工具。私钥 `b` 永不离开你的机器——卖家只卖算力。
Buyer-side tool for split-key vanity addresses. Your secret `b` never
leaves your machine — the seller provides GPU compute only.

## 0. 验证下载包 Verify your download

```bash
sha256sum -c SHA256SUMS.txt        # 校验必须 PASS / must say OK
```

Windows: `certutil -hashfile tron-tool.exe SHA256` 对比 SHA256SUMS.txt。

## 1. 生成买家密钥 Generate your secret

双击 `tron-tool`（无参数）进交互模式：先选语言（1=English / 2=中文），
主菜单同级四项——`1` 新订单（仅此路径问 pattern）、`2` 仅生成密钥、
`3` 验收取件、`6` 查看订单。只要密钥不要下单？选 `2` 即可，全程不问
pattern。下单则选 `1`：先输入定制（见下方语法），文件名按定制自动
生成（如 `b-repeat6.key`）。或显式命令：

```bash
tron-tool keygen -o b-repeat6.key
```

- 输出 `b-*.key`（0600）+ 打印公钥 `B`。**立刻备份——丢失 = 订单全损，卖家也无法恢复。**
- Back up the `b` file NOW: losing it forfeits the order; the seller cannot recover it.
- 更高保障：离线机生成（`--require-offline` / interactive 里选 `y`）。

## 2. 签名订单 Sign your order

交互菜单选 `1` 走完整下单路径（pattern → keygen → 订单一步到底），或：

```bash
tron-tool order -k b-repeat6.key -p 6 -o repeat6.tronorder
```

- `-p` 支持 §3.1 全部语法：**`repeat:<n>`** 尾号 n 位相同（裸数字 `8`
  亦可）、**`pair:<k>`** 对子连排（`pair:2`=AABB、`pair:3`=AABBCC）、
  **`alt:2`** 间隔对（ABAB）、**`suffix:<s>`** 指定后缀（如
  `suffix:8888`，2~8 位 base58 字符，无 `0 O I l`）。
  Pattern grammar: `repeat:<n>` (bare `<n>` ok), `pair:<k>` (AABB…),
  `alt:2` (ABAB), `suffix:<s>` (literal tail, 2–8 base58 chars).
- 命中概率即成本：`pair:2`/`alt:2` 最易（≈1/3,423）；`suffix:8888`
  ≈ 1/58⁴，算力开销 ≈ repeat:5。
- 输出 `.tronorder` + 回显指纹 `H`。**保管好 .tronorder——它是取货凭证。**
  The `.tronorder` is your pickup ticket — keep it safe.

## 3. 上传 + 付款 Upload & pay

在售卖页上传 `.tronorder`，核对页面显示的 `H` == 本机回显的 `H`，
然后向页面给出的专属地址支付 USDT-TRC20。

Upload the `.tronorder` on the vending page, check the shown `H` matches
your local `H`, then pay the displayed USDT amount to the bound address.

> ⚠ 永远不要上传 `b-*.key` / `priv.key` / 任何私钥文件——只上传 `.tronorder`。
> NEVER upload `b-*.key` / `priv.key` / any secret file — `.tronorder` only.

## 4. 取货验收 Collect & redeem

付款后 GPU 开工；在售卖页用 `H` 查询状态，交付后下载 `.tronspk` 包。
把 `.tronspk` 放进与 `b-*.key`、`.tronorder` 同一目录，交互菜单选 `3`——
工具自动扫描并配对（按交付包里的 B+pattern 匹配密钥与订单文件），
只需确认导出选项：

- `导出私钥到文件？` y → 写 `priv-<pattern>.key`（0600）；N → 不落盘
- `私钥二维码` 1=终端显示（扫码导入钱包）2=存 PNG 0=跳过

或显式命令：

```bash
tron-tool redeem -p pkg.tronspk -k b.key -e 6 --export-priv priv.key -o qr.png
```

- `-e` 必须与你订单里的 pattern 一致（同样是输数字即可）。
- 三段验收自动执行：卖家签名 → 交付地址确含 `b` 绑定 → 地址满足 pattern。
  全部通过才打印靓号地址并导出 `priv.key`（真正私钥 = b + d）。
- `priv.key` 可导入任意 TRON 钱包；二维码内容为**私钥**，用于扫码导入钱包。

## 常见问题 Troubleshooting

| 现象 Symptom | 原因/处理 Fix |
|---|---|
| `invalid pattern "6"` | 旧版本只认 `repeat:6`——升级到 v1.0.3+ 后数字直输即可 |
| `refusing to overwrite` | 输出文件已存在，换文件名或先移走旧文件（防误覆盖设计） |
| 忘了下单时的要求 | `tron-tool inspect -f my.tronorder`（或菜单选 `6`）查看 pattern/H/签名；售卖页查单也会显示「你的定制」 |
| redeem 报 pattern 不符 | `-e` 必须填你下单时的 pattern（如 `pair:2`），不是交付包里的字段 |
| macOS 拦截未签名二进制 | `xattr -d com.apple.quarantine tron-tool` |
| Windows SmartScreen 拦截 | 未签名新发布的正常提示：先验 SHA256（§0）→「更多信息」→「仍要运行」。SmartScreen blocks unsigned new releases: verify checksum first, then More info → Run anyway |

完整文档见 `README.md`；协议规范可独立审计 `spec/`（github repo）。
