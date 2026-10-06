#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  dsh-proof — 交互式推送（你自己跑，token 由你输入）
#
#  安全性质：
#    · token 用 `read -rsp` 隐藏输入，不回显
#    · 只存在当前 shell 变量里，不写入任何文件
#    · 通过 `sh -c` 的环境变量传给 git credential helper，不进入任何 argv
#    · 不修改全局 git 配置（credential.helper 用 `-c` 只对本次生效）
#    · 脚本结束时清空变量
#
#  用法：  ./scripts/push-interactive.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")/.."

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
warn() { printf '\033[33m%s\033[0m\n' "$*"; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

echo
bold "dsh-proof → GitHub 推送"
echo

# ── 1. 仓库地址 ──────────────────────────────────────────────────────────────
REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"
if [[ -n "$REMOTE_URL" ]]; then
  echo "当前 origin: $REMOTE_URL"
  read -rp "直接回车沿用，或输入新的 GitHub 仓库地址: " INPUT_URL
  [[ -n "${INPUT_URL:-}" ]] && REMOTE_URL="$INPUT_URL"
else
  read -rp "GitHub 仓库地址 (https://github.com/OWNER/REPO.git): " REMOTE_URL
fi

REMOTE_URL="${REMOTE_URL// /}"
if [[ -z "$REMOTE_URL" ]]; then
  err "仓库地址不能为空。"
  exit 2
fi
if [[ "$REMOTE_URL" != https://github.com/* ]]; then
  err "必须是 https://github.com/OWNER/REPO.git（SSH 地址用不了 token）。"
  err "如果你有 SSH key，直接 git push 就行，不需要这个脚本。"
  exit 2
fi
# 拒绝已经把凭据写进 URL 的情况
if [[ "$REMOTE_URL" == https://*:*@* ]]; then
  err "URL 里已经带了凭据 —— 拒绝执行。请用干净的 https://github.com/OWNER/REPO.git"
  exit 1
fi

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi
echo "✓ origin = $REMOTE_URL"
echo

# ── 2. token（隐藏输入）────────────────────────────────────────────────────
warn "接下来粘贴 token —— 终端不会显示任何字符，粘完直接回车，这是正常的。"
read -rsp "GitHub token (输入隐藏): " GH_TOKEN
echo
if [[ -z "$GH_TOKEN" ]]; then
  err "token 为空。"
  exit 2
fi
if [[ "$GH_TOKEN" != ghp_* && "$GH_TOKEN" != github_pat_* && "$GH_TOKEN" != gho_* ]]; then
  warn "提示：这看起来不像 GitHub PAT（通常以 ghp_ / github_pat_ 开头）。继续尝试。"
fi
echo "✓ 已接收（长度 ${#GH_TOKEN}，内容不回显、不保存）"
echo

# ── 3. 推送 ────────────────────────────────────────────────────────────────
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
bold "推送 $BRANCH → $REMOTE_URL"
echo

# credential.helper 的 `!` 片段由 git 用 sh -c 执行，GH_TOKEN 从环境展开，
# 因此 token 的值绝不会出现在 ps / argv / 任何文件里。
if git ls-remote --exit-code origin "$BRANCH" >/dev/null 2>&1; then
  PUSH_ARGS=(origin "$BRANCH")
else
  PUSH_ARGS=(-u origin "$BRANCH")
fi

set +e
# The empty `credential.helper=` RESETS the helper list first: without it, git
# appends our inline helper AFTER any system/global helper (e.g. Git Credential
# Manager). That has two failure modes: the stored credential wins and the
# typed token is silently unused, or a successful auth "approves" the token
# into GCM — writing it to disk, violating the zero-persistence promise above.
GH_TOKEN="$GH_TOKEN" git \
  -c credential.helper= \
  -c 'credential.helper=!f() { echo "username=x-access-token"; echo "password=$GH_TOKEN"; }; f' \
  -c credential.useHttpPath=true \
  push "${PUSH_ARGS[@]}" --follow-tags
STATUS=$?
set -e

# 立即清空
GH_TOKEN=''
unset GH_TOKEN

echo
if [[ $STATUS -eq 0 ]]; then
  bold "✅ 推送成功"
  echo
  warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  warn "现在请立刻去删除刚才那个 token："
  warn "  GitHub → Settings → Developer settings → Personal access tokens"
  warn "  → 找到它 → Delete"
  warn ""
  warn "然后如果还需要 token，新建一个 fine-grained PAT："
  warn "  Repository access → Only select repositories → 只选这一个"
  warn "  Permissions → Contents: Read and write（其他全不勾）"
  warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo
  echo "最后一步（仓库页面 → About → Settings → Topics）加上："
  bold "  dsh-plugin"
  echo "这是官方可发现性约定，社区 awesome 列表按这个标签收录。"
  echo
  echo "如果 CI 没自动跑：仓库 → Actions → 选 CI workflow → Run workflow"
else
  err "推送失败（退出码 $STATUS）。常见原因："
  err "  · token 已过期 / 被撤销"
  err "  · token 权限不含 Contents: write"
  err "  · 仓库不存在，或不是这个 token 能访问的仓库"
  err "  · 分支保护规则拒绝直接推 master"
  err "token 已从内存清除，可安全重试。"
  exit $STATUS
fi
