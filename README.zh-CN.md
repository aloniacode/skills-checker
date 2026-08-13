# skills-checker

本地 Agent / SKILL 配置文件安全检测工具（Rust 实现）。

递归扫描全局及指定目录下所有 Agent/SKILL 配置文件，检测四类安全隐患：

| 风险类型 | 说明 | 示例规则 |
|---|---|---|
| 🔴 远程数据上传 | 默认开启的向远程服务器发送本地数据的行为 | `requests.post`、`curl -X POST`、`upload()`、`multipart/form-data`、`webhook:` |
| 🔑 硬编码敏感信息 | API Key / Token / 密码明文 | `sk-*`、`AKIA*`、`ghp_*`、`xox*`、`AIza*`、`password = "..."` |
| 🌐 可疑 URL 外联 | 数据收集/隧道服务、裸 IP、遥测埋点 | `webhook.site`、`requestbin`、`ngrok`、裸 IP、`telemetry/collect` |
| ⚡ 危险命令执行 | 下载即执行、shell 注入、破坏性命令 | `curl \| sh`、`base64 -d \| sh`、`shell=True`、`os.system`、`rm -rf /`、编码 PowerShell |

## 快速开始

```bash
cargo build --release
./target/release/skills-checker                 # 扫描全局常见 Agent 配置目录
./target/release/skills-checker -d ~/.claude    # 指定目录（可多次 -d）
./target/release/skills-checker -d ./skills --json   # JSON 输出到 stdout
./target/release/skills-checker -d ./skills -o report.json   # 导出报告（扩展名自动推断格式）
./target/release/skills-checker -d ./skills -o report.html   # 导出可读的 HTML 报告
./target/release/skills-checker -d ./skills -o report.txt --format text
./target/release/skills-checker -d ./skills --fail-on high -q   # CI 集成
```

## 命令行参数

```
-d, --path <DIR>    指定扫描目录（可多次指定）；缺省扫描常见全局 Agent 配置目录
    --json          JSON 格式输出到 stdout
-o, --output <FILE> 导出报告到文件
    --format <FMT>  导出格式 auto|json|html|text（默认 auto，按扩展名推断）
    --no-cache      禁用增量缓存
-q, --quiet         安静模式（仅一行摘要）
-v, --verbose       显示命中的代码行
    --fail-on <LVL> 触发失败退出码的最低等级 critical|high|medium|low（默认 low）
```

全局默认扫描目录：`~/.claude`、`~/.coze`、`~/.cursor`、`~/.gemini`、`~/.codex`、
`~/.aider`、`~/.continue`、`~/.copilot`、`~/.config/{claude,coze,cursor,...}` 等，
亦可通过环境变量 `SKILLS_CHECKER_PATHS`（OS 路径分隔符）追加自定义目录。

## 退出码（CI 友好）

| 退出码 | 含义 |
|---|---|
| 0 | 未发现达到 `--fail-on` 阈值的风险 |
| 1 | 发现达到阈值的风险 |
| 2 | 运行错误（参数/目录无效） |

## 工程结构

```
src/
├── main.rs      # 入口：clap 参数解析、扫描编排、退出码
├── models.rs    # 公共数据结构（Severity/RiskType/Finding/ScanResult/缓存）
├── rules.rs     # 20+ 条检测规则（正则 + 等级 + 描述 + 修复建议）
├── scanner.rs   # 目录发现、文件过滤、并行扫描、增量缓存
└── report.rs    # 终端彩色输出、JSON/文本导出
```

## 性能设计

- **并行扫描**：`rayon` 按 CPU 核数并行读取与匹配，规则集编译一次全局复用
- **增量缓存**：`~/.cache/skills-checker/cache.json` 记录每个文件的
  `(size, mtime)` 指纹，未变更文件直接复用上次结果（秒级二次扫描）；
  内置**规则指纹**校验，规则更新后旧缓存自动失效
- **文件过滤**：仅扫描名称含 skill/agent/mcp 或位于 skill 目录的文本文件，
  自动跳过 `.git`/`node_modules`/`target` 等目录及超过 10MB 的大文件

## 降噪机制

- 占位符/示例值（`your-*`、`example`、`<token>`、`xxx`、`******` 等）不告警
- URL 白名单：文档/官方域名（github.com、docs.rs、pypi.org 等）低危不告警
- `--fail-on` 可调节 CI 灵敏度，`-q` 供脚本消费

## 开发

```bash
cargo test        # 单元测试
cargo clippy      # lint（零警告）
cargo fmt         # 格式化
```

## 打包为 npm 包分发

该 CLI 可发布到 npm registry 便于安装分发，采用与 esbuild / oxlint 相同的模式：
npm 包内打包原生 Rust 二进制 + 零依赖 Node shim。

```
bin/skills-checker.js              # 跨平台 shim：定位并调用原生二进制
bin/<platform>-<arch>/skills-checker(.exe)   # 预编译原生二进制
scripts/copy-bin.js                # 将 target/release 产物复制进 npm 布局
scripts/install.js                 # postinstall：校验或可选下载二进制
scripts/merge-artifacts.js         # CI：合并各平台构建产物
.github/workflows/release.yml      # 5 平台构建矩阵 + 自动 npm publish
```

支持平台：`win32-x64`、`linux-x64`、`linux-arm64`、`darwin-x64`、`darwin-arm64`。

### 本地构建与测试

```bash
npm run build:bin                  # cargo build --release + 复制到 bin/
npm run test:bin                   # node bin/skills-checker.js --version
npm pack --dry-run                 # 查看压缩包内容
```

### 发布

方式 A — 手动（仅当前平台）：

```bash
npm login
npm run build:bin
npm publish --access public
```

方式 B — CI 自动（推荐，覆盖全部 5 平台）：

1. 推送标签：`git tag v0.1.0 && git push --tags`
2. `.github/workflows/release.yml` 自动构建各平台二进制并合并发布到 npm
   （需在仓库设置中配置 `secrets.NPM_TOKEN`）
3. 包版本自动与 git tag 同步

### 安装使用

```bash
npm install -g skills-checker
skills-checker -d ./skills --json         # 机器可读 JSON
skills-checker -d ./skills -o report.html # 自包含可读 HTML 报告
```

HTML 报告为单个自包含文件（内联 CSS/JS，无外部依赖），包含等级徽章、
按文件分组、可点击的等级筛选与深色模式适配——适合分享给非 CLI 用户阅读。

若平台无匹配的预编译二进制，`postinstall` 会输出指引：
`npm run build:bin`（本地构建）或设置 `SKILLS_CHECKER_BIN_URL` 从 GitHub
Release 资产下载。

## 语言切换

[English](README.md) · [简体中文](README.zh-CN.md)
