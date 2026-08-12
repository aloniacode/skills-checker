//! 风险检测规则库
//!
//! 每条规则包含：规则 ID、风险类型、风险等级、正则模式、描述、修复建议。
//! 规则为静态编译一次（LazyLock），供所有文件并行复用。

use crate::models::{RiskType, Severity};
use regex::Regex;
use std::sync::LazyLock;

pub struct Rule {
    pub id: &'static str,
    pub risk_type: RiskType,
    pub severity: Severity,
    pub pattern: &'static str,
    pub description: &'static str,
    pub fix: &'static str,
}

pub struct CompiledRule {
    pub rule: Rule,
    pub regex: Regex,
}

/// 判断一个字符串是否疑似占位符/示例值（命中则降低告警可信度）
pub fn is_placeholder(value: &str) -> bool {
    let v = value.trim_matches(|c| c == '\'' || c == '"' || c == '`');
    let v_lower = v.to_ascii_lowercase();
    if v.is_empty() {
        return true;
    }
    if v_lower.contains("your_")
        || v_lower.contains("your-")
        || v_lower.contains("example")
        || v_lower.contains("placeholder")
        || v_lower.contains("changeme")
        || v_lower.contains("replace_me")
        || v_lower.contains("<")
        || v_lower.contains(">")
        || v_lower.contains("xxx")
        || v_lower.contains("dummy")
        || v_lower.contains("test_key")
        || v_lower.contains("fake")
    {
        return true;
    }
    // 常见占位模式：重复字符、长度极短
    let bytes = v_lower.as_bytes();
    if bytes.len() <= 4 {
        return true;
    }
    let first = bytes[0];
    if bytes.iter().all(|&b| b == first) {
        return true;
    }
    false
}

pub const RULES: &[Rule] = &[
    // ================= SEC-1xx 硬编码敏感信息 =================
    Rule {
        id: "SEC-101",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::High,
        pattern: r#"(?i)(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|bearer)\s*[:=]\s*["'][^"'\s]{8,}["']"#,
        description: "配置中硬编码了疑似密钥/Token，可能被未授权方获取。",
        fix: "改用环境变量注入（如 ${API_KEY}）或密钥管理服务（Vault/Secret Manager），并从仓库历史中清除已泄露的密钥。",
    },
    Rule {
        id: "SEC-102",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Critical,
        pattern: r#"(?i)\bpassword\s*[:=]\s*["'][^"'\s]{6,}["']"#,
        description: "配置中硬编码了明文密码。",
        fix: "立即轮换该密码；改为通过环境变量或安全凭据存储引用，切勿写入配置文件。",
    },
    Rule {
        id: "SEC-103",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Critical,
        pattern: r"\bsk-[A-Za-z0-9_-]{20,}\b",
        description: "疑似 OpenAI/Anthropic 等 AI 服务 API Key（sk- 前缀）。",
        fix: "撤销并重新签发该密钥；使用环境变量引用，确保密钥不进入版本控制。",
    },
    Rule {
        id: "SEC-104",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Critical,
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
        description: "疑似 AWS Access Key ID。",
        fix: "在 AWS IAM 中吊销该密钥并轮换；改用 IAM Role 或环境变量。",
    },
    Rule {
        id: "SEC-105",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Critical,
        pattern: r"\bghp_[A-Za-z0-9]{36}\b",
        description: "疑似 GitHub Personal Access Token。",
        fix: "在 GitHub Settings 中吊销该 Token；改用 GitHub CLI/环境变量注入。",
    },
    Rule {
        id: "SEC-106",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Critical,
        pattern: r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        description: "疑似 Slack Bot/User Token。",
        fix: "吊销并重新生成 Slack Token；通过环境变量注入。",
    },
    Rule {
        id: "SEC-107",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Critical,
        pattern: r"\bAIza[0-9A-Za-z_-]{35}\b",
        description: "疑似 Google API Key。",
        fix: "在 Google Cloud Console 吊销该 Key；使用环境变量或 Secret Manager。",
    },
    Rule {
        id: "SEC-108",
        risk_type: RiskType::HardcodedSecret,
        severity: Severity::Medium,
        pattern: r#"(?i)\b(token|secret)\s*[:=]\s*["'][^"'\s]{12,}["']"#,
        description: "疑似内嵌 Token/Secret 值。",
        fix: "确认是否真实凭据；如是，迁移到环境变量并轮换。",
    },

    // ================= SEC-2xx 远程数据上传 =================
    Rule {
        id: "SEC-201",
        risk_type: RiskType::RemoteUpload,
        severity: Severity::High,
        pattern: r#"(?i)\b(requests|urllib|httpx|aiohttp|axios|http)\s*[\.\(\s]*\s*(post|put|patch)\s*\(|\bcurl\s+[^\n"']*-X\s+(POST|PUT|PATCH)\b|fetch\(\s*["'][^"']+["']\s*,\s*\{[^}\n]*method\s*:\s*["'](POST|PUT|PATCH)["']"#,
        description: "检测到向远程服务器发送数据的调用（POST/PUT/PATCH），Agent 可能默认上传本地数据。",
        fix: "确认该上传行为是否默认开启；应默认关闭并在上传前明确征得用户同意，敏感数据应脱敏。",
    },
    Rule {
        id: "SEC-202",
        risk_type: RiskType::RemoteUpload,
        severity: Severity::High,
        pattern: r#"(?i)\b(upload|upload_file|upload_bytes|upload_to|send_file|send_message|post_data|report_data)\s*\([^)]{0,120}["']?https?://"#,
        description: "发现文件/数据上传逻辑（upload/send 调用指向 URL）。",
        fix: "审查上传目标与触发条件；确保默认不上传，上传前有用户授权与数据脱敏。",
    },
    Rule {
        id: "SEC-203",
        risk_type: RiskType::RemoteUpload,
        severity: Severity::High,
        pattern: r#"(?i)multipart/form-data|Content-Disposition\s*[:=]\s*["']?attachment"#,
        description: "检测到 multipart/附件上传构造，疑似自动外传文件。",
        fix: "确认文件上传是否默认发生；改为显式询问用户后再上传。",
    },
    Rule {
        id: "SEC-204",
        risk_type: RiskType::RemoteUpload,
        severity: Severity::Medium,
        pattern: r#"(?i)\bwebhook\s*[:=]\s*["']?https?://"#,
        description: "配置了 Webhook 回调地址，事件数据可能被自动推送至该地址。",
        fix: "确认 Webhook 用途与归属；非必要关闭，或仅推送脱敏/必要字段。",
    },

    // ================= SEC-3xx 可疑 URL 外联 =================
    Rule {
        id: "SEC-301",
        risk_type: RiskType::SuspiciousUrl,
        severity: Severity::High,
        pattern: r#"(?i)https?://(webhook\.site|requestbin(\.com)?|pipedream|beeceptor|interact\.sh|webhook\.io|hookbin|ngrok[^/"'\s]*|localtunnel|serveo|localhost\.run|tunnel\.dev)"#,
        description: "指向数据收集/隧道转发服务，常用于窃取或转发数据，非常可疑。",
        fix: "确认该地址的来源与用途；若非必要请删除，谨防数据被第三方截获。",
    },
    Rule {
        id: "SEC-302",
        risk_type: RiskType::SuspiciousUrl,
        severity: Severity::High,
        pattern: r#"(?i)https?://\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?(/[^\s"'<>]*)?\b"#,
        description: "发现裸 IP 直连地址（可能绕过域名审计/证书校验）。",
        fix: "改用受信任的正式域名；核实该 IP 归属与用途。",
    },
    Rule {
        id: "SEC-303",
        risk_type: RiskType::SuspiciousUrl,
        severity: Severity::Medium,
        pattern: r#"(?i)https?://[^\s"'<>)]*(telemetry|analytics|tracking|collect|beacon|pixel|metrics|ingest)[^\s"'<>)]*"#,
        description: "检测到遥测/埋点/数据采集类端点，可能静默上报用户环境数据。",
        fix: "确认数据采集是否默认开启并告知用户；提供开关并默认关闭，上报内容需脱敏。",
    },
    Rule {
        id: "SEC-304",
        risk_type: RiskType::SuspiciousUrl,
        severity: Severity::Low,
        pattern: r#"(?i)\bhttps?://[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(:[0-9]{1,5})?(/[^\s"'<>)]*)?"#,
        description: "配置中出现外部 URL 外联（自动检测为低风险提示）。",
        fix: "确认该外联必要且受信任；Agent 配置中的外部调用应尽量默认关闭。",
    },

    // ================= SEC-4xx 危险命令执行 =================
    Rule {
        id: "SEC-401",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Critical,
        pattern: r#"(?i)(curl|wget|aria2c)\s+[^|;"'\n]*\|\s*(ba)?sh\b"#,
        description: "发现「下载即执行」管道（curl | sh），可被供应链攻击利用。",
        fix: "改为先下载校验哈希与签名后再执行；优先使用包管理器的官方源。",
    },
    Rule {
        id: "SEC-402",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Critical,
        pattern: r#"(?i)base64\s+(-[^\s]*\s+)*-\s*d[^\s]*[^|;"'\n]*\|\s*sh\b"#,
        description: "发现 base64 解码后直接执行的混淆命令，高度可疑。",
        fix: "解码审查命令内容；移除该执行链。",
    },
    Rule {
        id: "SEC-403",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Critical,
        pattern: r#"(?i)powershell\s+[^\n]*(encodedcommand|-enc\b|-e\b)|(Invoke-Expression|iex\s+\()"#,
        description: "发现 PowerShell 编码命令/动态表达式执行，常用于隐藏恶意载荷。",
        fix: "审查实际执行内容；避免在 Agent 配置中使用编码执行。",
    },
    Rule {
        id: "SEC-404",
        risk_type: RiskType::DangerousExec,
        severity: Severity::High,
        pattern: r#"(?i)\b(os\.system|subprocess\.(run|call|Popen|check_output|popen)|child_process\.(exec|execSync|spawn|spawnSync)|process\.exec|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("#,
        description: "发现直接调用系统命令执行接口。",
        fix: "审查命令参数是否含用户可控输入（防命令注入）；优先使用安全库函数。",
    },
    Rule {
        id: "SEC-405",
        risk_type: RiskType::DangerousExec,
        severity: Severity::High,
        pattern: r#"(?i)shell\s*=\s*True\b|shell\s*:\s*true\b"#,
        description: "subprocess 以 shell 模式执行，存在命令注入风险。",
        fix: "不要开启 shell 模式，改为参数列表形式传参。",
    },
    Rule {
        id: "SEC-406",
        risk_type: RiskType::DangerousExec,
        severity: Severity::High,
        pattern: r#"(?i)(/bin/(ba)?sh\s+-c\s+|cmd\.exe\s+/(c|k)\s+|cmd\s+/(c|k)\s+)"#,
        description: "发现 shell -c / cmd /c 形式的命令拼接执行。",
        fix: "审查拼接内容；禁止将外部输入拼入 shell 命令。",
    },
    Rule {
        id: "SEC-407",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Critical,
        pattern: r#"(?i)\brm\s+-rf\s+/\b"#,
        description: "发现删除根目录的危险命令（rm -rf /）。",
        fix: "立即移除；危险破坏性命令不应出现在 Agent 配置中。",
    },
    Rule {
        id: "SEC-408",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Medium,
        pattern: r#"(?i)\bchmod\s+777\b|chmod\s+-R\s+[0-7]+"#,
        description: "发现权限全开/递归赋权命令，可能造成本地越权风险。",
        fix: "使用最小必要权限（如 700/600），避免 777。",
    },
    Rule {
        id: "SEC-409",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Medium,
        pattern: r#"(?i)\b(eval|exec|exec_|new_function)\s*\("#,
        description: "发现动态代码执行（eval/exec），可能执行不可信输入。",
        fix: "避免对不可信内容使用 eval/exec；改用安全解析方案。",
    },
    Rule {
        id: "SEC-410",
        risk_type: RiskType::DangerousExec,
        severity: Severity::Medium,
        pattern: r#"(?i)\bCommand::new\s*\(|\bProcess::start\s*\(|child_process\.spawn\b|process\.spawn\b"#,
        description: "发现启动外部进程的代码。",
        fix: "审查被启动程序与参数来源；限制为白名单命令。",
    },
];

/// 全局编译后的规则集（懒加载、进程内共享）
pub static COMPILED: LazyLock<Vec<CompiledRule>> = LazyLock::new(|| {
    RULES
        .iter()
        .filter_map(|r| match Regex::new(r.pattern) {
            Ok(regex) => Some(CompiledRule {
                rule: Rule {
                    id: r.id,
                    risk_type: r.risk_type,
                    severity: r.severity,
                    pattern: r.pattern,
                    description: r.description,
                    fix: r.fix,
                },
                regex,
            }),
            Err(e) => {
                eprintln!("[warn] 规则 {} 编译失败: {}", r.id, e);
                None
            }
        })
        .collect()
});
