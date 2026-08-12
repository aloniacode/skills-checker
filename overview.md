# skills-checker 交付说明

## 完成内容

在 `D:\WorkSpace\skills-checker` 下初始化并完成了一个 Rust CLI 安全检测工具 `skills-checker`，
用于扫描本地 Agent/SKILL 配置文件中的安全隐患。release 构建通过、clippy 零警告、
单元测试通过、冒烟测试全绿。

## 核心能力（均经实测验证）

1. **默认全局扫描**：自动发现 `~/.claude`、`~/.coze`、`~/.cursor`、`~/.gemini`、
   `~/.config/{claude,coze,cursor,...}` 等常见 Agent 配置目录；`SKILLS_CHECKER_PATHS`
   环境变量可追加目录；本机实测默认模式 615ms 扫完 473 个文件。
2. **三类检测**（20 条规则，按 `SEC-xxx` 编号）：
   - 远程数据上传（POST/PUT/上传调用/multipart/webhook）
   - 硬编码敏感信息（sk-/AKIA/ghp_/xox/AIza/password 等，占位符自动降噪）
   - 可疑 URL 外联 + 危险命令执行（curl|sh、shell=True、rm -rf / 等）
3. **`-d/--path` 指定目录**（可重复），文件过滤只扫 skill/agent 相关文本文件。
4. **结构化报告**：文件路径 + 行号 + 等级 + 类型 + 规则号 + 描述 + 修复建议。
5. **输出**：终端彩色分级、`--json` stdout、`-o` 导出 json/text（扩展名自动推断）。
6. **性能**：rayon 并行扫描 + `~/.cache/skills-checker/cache.json` 增量缓存
   （size+mtime 指纹，规则更新自动失效）。
7. **退出码**：0=无风险，1=发现达到 `--fail-on`（默认 low）阈值的风险，2=运行错误。

## 实测数据

- 测试样本（test-fixtures）：20 处风险全部命中，占位符/白名单域名正确忽略
- 干净目录：exit=0；风险目录：exit=1；二次扫描 cache_hits=3（秒级）

## 工程结构

```
src/main.rs      入口与参数解析（clap）
src/models.rs    数据结构（Severity/RiskType/Finding/ScanResult/缓存）
src/rules.rs     20 条检测规则（编译期一次编译，全局复用）
src/scanner.rs   目录发现/并行扫描/增量缓存
src/report.rs    终端彩色 + JSON/文本导出
test-fixtures/   隐患样本（冒烟测试用）
test-clean/      干净样本
```

## 已知限制

- 误报可控但存在：SEC-304 低危 URL 提示依赖白名单，自定义可信域名需改代码
- Windows 下路径分隔符显示为 `\`（正常）
- 大文件（>10MB）跳过不扫描
