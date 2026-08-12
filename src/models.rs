//! 公共数据结构定义

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// 风险等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
        }
    }

    /// 是否达到指定门槛（含等于）
    pub fn meets(self, threshold: Severity) -> bool {
        self.rank() >= threshold.rank()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
            }
        )
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "critical" | "crit" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" | "med" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            _ => Err(format!(
                "未知风险等级: {s}（可选: critical/high/medium/low）"
            )),
        }
    }
}

/// 风险类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskType {
    /// 默认开启的远程数据上传行为
    RemoteUpload,
    /// 硬编码的敏感信息（API Key / Token / 密码）
    HardcodedSecret,
    /// 可疑 URL 外联
    SuspiciousUrl,
    /// 危险命令执行 / 危险代码片段
    DangerousExec,
}

impl fmt::Display for RiskType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RiskType::RemoteUpload => "远程数据上传",
                RiskType::HardcodedSecret => "硬编码敏感信息",
                RiskType::SuspiciousUrl => "可疑 URL 外联",
                RiskType::DangerousExec => "危险命令执行",
            }
        )
    }
}

/// 单条风险发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// 相对/展示用文件路径
    pub file: String,
    /// 行号（从 1 开始）
    pub line: usize,
    /// 风险等级
    pub severity: Severity,
    /// 风险类型
    pub risk_type: RiskType,
    /// 命中规则 ID，如 SEC-001
    pub rule_id: String,
    /// 风险描述
    pub description: String,
    /// 命中的代码行原文（截断）
    pub snippet: String,
    /// 修复建议
    pub fix: String,
}

/// 单个文件的扫描结果（用于增量缓存复用）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub size: u64,
    pub mtime_ns: i128,
    pub findings: Vec<Finding>,
}

/// 整体扫描结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    /// 扫描时间（Unix 秒）
    pub scanned_at: u64,
    /// 实际扫描的根目录
    pub roots: Vec<String>,
    /// 扫描的文件数
    pub scanned_files: usize,
    /// 读取的总字节数
    pub scanned_bytes: u64,
    /// 缓存命中的文件数
    pub cache_hits: usize,
    /// 扫描耗时（毫秒）
    pub duration_ms: u64,
    /// 全部风险发现
    pub findings: Vec<Finding>,
}

impl ScanResult {
    /// 达到某个等级门槛的发现数
    pub fn count_ge(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity.meets(threshold))
            .count()
    }

    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// 增量缓存文件结构
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheFile {
    pub version: u32,
    /// 规则集指纹：规则更新后旧缓存自动失效
    pub rules_hash: String,
    pub entries: std::collections::HashMap<String, FileResult>,
}

/// 解析 Severity 的辅助函数（供 clap value_parser 使用）
pub fn parse_severity(s: &str) -> Result<Severity, String> {
    s.parse()
}

/// 汇总目录树里所有文件路径（仅类型声明辅助）
#[allow(dead_code)]
pub type PathList = Vec<PathBuf>;
