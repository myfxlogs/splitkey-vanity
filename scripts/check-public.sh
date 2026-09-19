#!/bin/sh
# check-public.sh — 公开发布前检查：禁止治理文档/私有文档/秘密材料进入本仓库。
# 用法：scripts/check-public.sh（pre-push 钩子与 CI 共用；手动随时可跑）
# 退出码：0=干净；1=发现违禁内容。

set -eu
cd "$(git rev-parse --show-toplevel)"

fail=0
report() { echo "FORBIDDEN: $1"; fail=1; }

# ── 1. 路径/文件名黑名单 ──
for f in $(git ls-files); do
    base=$(basename "$f")
    case "$f" in
        .devin/*|docs/*|*/docs/*|keys/*|secrets/*) report "$f (private dir)" ;;
    esac
    case "$base" in
        AGENTS.md|AUDIT_GATE.md|DESIGN.md|STATE.md|decisions.md|立项清单.md)
            report "$f (governance doc)" ;;
        audit-*.md|review*.md)
            report "$f (audit/review record)" ;;
        *.key|*.pem|*.tronorder)
            report "$f (secret material)" ;;
    esac
done

# ── 2. 内容检查：裸标量文件（单文件=64 hex，b/priv/Ed25519 私钥形态）──
for f in $(git ls-files); do
    # 只查小文件，跳过二进制
    size=$(wc -c < "$f" 2>/dev/null || echo 999999)
    [ "$size" -le 100 ] || continue
    body=$(tr -d '[:space:]' < "$f")
    case "$body" in
        *[!0-9a-fA-F]*) ;;                      # 含非 hex 字符 → 不是裸标量
        ????????????????????????????????????????????????????????????????)
            if [ ${#body} -eq 64 ]; then
                report "$f (bare 64-hex scalar file)"
            fi ;;
    esac
done

if [ "$fail" -eq 0 ]; then
    echo "check-public: clean ($(git ls-files | wc -l) tracked files)"
fi
exit "$fail"
