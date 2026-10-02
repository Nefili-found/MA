# WORKFLOW.md — 版本记录工作流

面向本仓库（根目录 = `experiment framework/`）。目标：让每个可复现的代码快照都被 Git 记录。
日期约定：与 `CHANGE.md` 一致，按文件/系统时间记录（本机无远端仓库）。

## 1. 仓库约定
- 仓库根：`experiment framework/`，主分支 `main`。
- 忽略规则见 `.gitignore`：`.venv/`、`.idea/`、`.env`、`memory.db`、`output/*.json`、`Framework - 副本/` 等。
- 入库范围：`Framework/` 代码骨架 + `CHANGE.md` + `prompt and report/` + `文档（person）/` + `improvement/`。

## 2. 日常流程（每次改动）
```bash
git status                 # 看改了什么
git diff                   # 看具体改动
git add -A                 # 或 git add <指定文件>
git commit -m "<type>: <说明>"
```
- 一个逻辑改动 = 一个提交。
- 提交前确认 `git status` 中**没有** `.env` / `memory.db` / `.venv`。

## 3. 提交信息规范（精简 Conventional Commits）
| type | 用途 |
| --- | --- |
| feat | 新功能 |
| fix | 修 bug |
| docs | 文档（含 `QUESTION.md` / `CHANGE.md` / `WORKFLOW.md`）|
| refactor | 重构（不改行为）|
| chore | 杂项（初始化、配置）|
| test | 测试 |

格式：`<type>: <一句话说明>`，例：`feat: 接入 verify_taint 真实实现`。

## 4. 版本（里程碑）—— 打标签
每个“版本” = 一个带注释 tag：
```bash
git tag -a v0.1.0 -m "首个可运行骨架"
git tag -a v0.2.0 -m "A/B/C Prompt 已填写 + D 汇总流程"
```
- 查看：`git tag`、`git show v0.1.0`
- 回到某版本查看：`git switch --detach v0.1.0`（回到最新：`git switch main`）

## 5. 与 CHANGE.md 联动
- 每次提交 / 发版，在 `CHANGE.md` **顶部**按**日期**追加一条（标题 `## YYYY-MM-DD`，最新在上）。
- 保持“版本 = tag，过程 = CHANGE.md 日期条目”的双轨记录。

## 6. 常用命令速查
```bash
git status                       # 状态
git diff                         # 未暂存改动
git log --oneline --stat         # 历史（含文件统计）
git log --oneline --graph --all  # 图形化历史
git tag -a vX.Y.Z -m ""          # 打版本
git show <tag|commit>            # 查看某版本
git restore <file>               # 撤销工作区改动
git rm --cached <file>           # 停止跟踪（保留本地文件）
```

## 7. 回滚 / 注意事项
- 尚未 push 到远端，任何误操作可直接删除仓库根的 `.git/` 重来。
- 若发现误提交了密钥：`git rm --cached Framework/config/.env` → 提交 → **轮换该密钥**。
- Windows：行尾由 `core.autocrlf=true` 处理；中文文件名由 `core.quotepath=false` 正常显示。
- 若要把 `Framework - 副本/` 或大 PDF 纳入/移出：编辑根 `.gitignore` 后重新 `git add`。
```bash
# 例：把已提交的大文件移出跟踪（保留本地）
git rm --cached "prompt and report/xxx.pdf"
```
