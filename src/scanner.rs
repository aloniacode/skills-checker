//! 目录发现、并行扫描与增量缓存

use crate::models::{CacheFile, FileResult, Finding, RiskType};
use crate::rules::{self, is_placeholder, CompiledRule};
use rayon::prelude::*;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 扫描时跳过的目录（不进入）
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".cache",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".next",
    ".turbo",
    ".svn",
    "vendor",
];

/// 允许扫描的文本扩展名
const ALLOWED_EXTS: &[&str] = &[
    "md",
    "markdown",
    "yaml",
    "yml",
    "json",
    "jsonc",
    "toml",
    "txt",
    "sh",
    "py",
    "js",
    "ts",
    "tsx",
    "jsx",
    "ps1",
    "bat",
    "cmd",
    "zsh",
    "fish",
    "rb",
    "lua",
    "go",
    "rs",
    "cfg",
    "ini",
    "conf",
    "env",
    "html",
    "xml",
    "properties",
    "tool",
    "mcp",
];

/// 单文件最大扫描字节数（超过则跳过并提示，防止二进制/超大文件拖垮扫描）
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// SEC-304 低危 URL 外联的域名白名单（文档/官方地址不告警）
const SAFE_URL_DOMAINS: &[&str] = &[
    "example.com",
    "example.org",
    "localhost",
    "127.0.0.1",
    "w3.org",
    "json-schema.org",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "stackoverflow.com",
    "developer.mozilla.org",
    "docs.rs",
    "crates.io",
    "npmjs.com",
    "pypi.org",
    "python.org",
    "rust-lang.org",
    "openai.com",
    "anthropic.com",
    "claude.ai",
    "coze.com",
    "coze.cn",
    "cursor.com",
    "google.com",
    "microsoft.com",
    "react.dev",
    "vuejs.org",
    "tailwindcss.com",
    "nodejs.org",
    "typescriptlang.org",
    "schema.org",
    "aijiangshan.com",
    "docker.com",
    "kubernetes.io",
    "zhihu.com",
    "wikipedia.org",
    "apple.com",
    "mozilla.org",
    "iso.org",
    "ietf.org",
    "rfc-editor.org",
];

fn is_safe_url_domain(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    SAFE_URL_DOMAINS.iter().any(|d| {
        lower.starts_with(d)
            || lower.contains(&format!("://{}", d))
            || lower.contains(&format!(".{}", d))
    })
}

/// 获取当前用户主目录
pub fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("USERPROFILE") {
        return Some(PathBuf::from(h));
    }
    if let Some(h) = std::env::var_os("HOME") {
        return Some(PathBuf::from(h));
    }
    None
}

/// 默认全局扫描目录：常见 Agent 配置目录
pub fn default_search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(home) = home_dir() {
        // 顶层 dotdir
        for d in [
            ".claude",
            ".coze",
            ".cursor",
            ".gemini",
            ".codex",
            ".aider",
            ".continue",
            ".copilot",
            ".windsurf",
            ".trae",
            ".qwen",
            ".agent",
            ".codebuddy",
            ".zed",
            ".opencode",
            ".config",
        ] {
            let p = home.join(d);
            if p.is_dir() {
                dirs.push(p);
            }
        }
        // ~/.config 下常见 agent 子目录
        for d in [
            "claude",
            "coze",
            "cursor",
            "gemini",
            "codex",
            "opencode",
            "codebuddy",
            "continue",
            "copilot",
            "agent",
            "zed",
            "aider",
            "qwen",
            "windsurf",
        ] {
            let p = home.join(".config").join(d);
            if p.is_dir() {
                dirs.push(p);
            }
        }
    }
    // 环境变量扩展
    if let Ok(extra) = std::env::var("SKILLS_CHECKER_PATHS") {
        for p in std::env::split_paths(&extra) {
            if p.is_dir() {
                dirs.push(p);
            }
        }
    }
    // 去重并保持顺序
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

/// 是否为需要纳入扫描的文件
pub fn is_skill_file(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    let segments: Vec<&str> = lower.split(['/', '\\']).collect();
    // 目录命中 agent/skill 关键词即视为配置目录（如 ~/.claude/config.yaml）
    let dir_hit = segments.iter().any(|s| {
        ["skill", "agent", "mcp", "claude", "coze", "cursor", "gemini", "codex", "copilot",
         "opencode", "windsurf", "aider", "qwen", "trae", "zed", "codebuddy"]
            .iter()
            .any(|kw| s.contains(kw))
    });
    let name = segments.last().unwrap_or(&"");
    let name_matches = name.contains("skill") || name.contains("agent") || name.contains("mcp");
    if !(dir_hit || name_matches) {
        return false;
    }
    // 扩展名过滤
    match path.extension() {
        Some(ext) => {
            let e = ext.to_string_lossy().to_ascii_lowercase();
            ALLOWED_EXTS.contains(&e.as_str())
        }
        None => false,
    }
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIRS.contains(&name) || name.starts_with('.') && name != ".config"
}

/// 递归收集 SKILL 相关文件
fn collect_files(root: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue, // 无权限/不存在则跳过
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !should_skip_dir(&name) {
                    stack.push(path);
                }
            } else if ft.is_file() && is_skill_file(&path) {
                out.push(path);
            }
        }
    }
    Ok(())
}

/// 增量缓存存储路径：~/.cache/skills-checker/cache.json
fn cache_file_path() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".cache").join("skills-checker").join("cache.json"))
}

/// 扫描逻辑版本：降噪/过滤等非规则逻辑变更时手动 +1，使旧缓存失效
const SCAN_LOGIC_VERSION: u32 = 1;

/// 规则集指纹：规则 id/等级/模式与扫描逻辑版本混合哈希，变更即失效
fn rules_fingerprint() -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    SCAN_LOGIC_VERSION.hash(&mut hasher);
    for r in rules::COMPILED.iter() {
        r.rule.id.hash(&mut hasher);
        r.rule.severity.rank().hash(&mut hasher);
        r.rule.pattern.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

pub fn load_cache() -> CacheFile {
    let Some(p) = cache_file_path() else {
        return CacheFile::default();
    };
    let cache: CacheFile = match fs::read_to_string(&p) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => CacheFile::default(),
    };
    // 规则集变化时丢弃整个缓存，避免陈旧结果
    if cache.rules_hash != rules_fingerprint() {
        return CacheFile::default();
    }
    cache
}

pub fn save_cache(cache: &CacheFile) {
    let Some(p) = cache_file_path() else { return };
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string(cache) {
        let _ = fs::write(p, text);
    }
}

/// 对单行文本执行一条规则，返回匹配区间（用于提取命中值）
fn match_on_line<'a>(rule: &CompiledRule, line: &'a str) -> Option<regex::Match<'a>> {
    rule.regex.find(line)
}

/// 对单行执行全部规则，返回本行命中（已做占位符/白名单过滤与行内去重）
fn check_line(
    rule: &CompiledRule,
    line_no: usize,
    line: &str,
    file_display: &str,
    out: &mut Vec<Finding>,
) {
    let Some(m) = match_on_line(rule, line) else {
        return;
    };
    let snippet = line.trim().chars().take(220).collect::<String>();

    // 硬编码密钥类：占位符值降噪（提取引号内/等号后的值再判断）
    if matches!(rule.rule.risk_type, RiskType::HardcodedSecret) {
        let value = extract_secret_value(m.as_str());
        if is_placeholder(&value) {
            return;
        }
    }
    // 低危 URL 外联：白名单域名降噪
    if rule.rule.id == "SEC-304" {
        if let Some(url) = extract_first_url(m.as_str()) {
            if is_safe_url_domain(&url) {
                return;
            }
        }
    }

    // 行内去重：同一行同一规则只报一次
    if out
        .iter()
        .any(|f| f.rule_id == rule.rule.id && f.line == line_no)
    {
        return;
    }

    out.push(Finding {
        file: file_display.to_string(),
        line: line_no,
        severity: rule.rule.severity,
        risk_type: rule.rule.risk_type,
        rule_id: rule.rule.id.to_string(),
        description: rule.rule.description.to_string(),
        snippet,
        fix: rule.rule.fix.to_string(),
    });
}

fn extract_first_url(text: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?i)https?://[^\s"'<>)]+"#).ok()?;
    re.find(text).map(|m| m.as_str().to_string())
}

/// 从密钥类匹配串中提取真实值：优先取引号对内的内容，退化取 [: =] 后的部分
fn extract_secret_value(s: &str) -> String {
    if let Some(close) = s.rfind(['"', '\'', '`']) {
        let quote = s[close..].chars().next().unwrap();
        if let Some(open) = s[..close].rfind(quote) {
            return s[open + 1..close].to_string();
        }
    }
    if let Some(idx) = s.rfind([':', '=']) {
        return s[idx + 1..].trim().trim_matches(|c| c == '"' || c == '\'').to_string();
    }
    s.to_string()
}

/// 扫描单个文件，返回 FileResult（含全部发现）
fn scan_file(path: &Path, root: &Path) -> FileResult {
    let display = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();

    let (size, mtime_ns) = match fs::metadata(path) {
        Ok(md) => (
            md.len(),
            md.modified()
                .unwrap_or(UNIX_EPOCH)
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as i128)
                .unwrap_or(0),
        ),
        Err(_) => (0, 0),
    };

    let mut findings = Vec::new();
    if size > MAX_FILE_BYTES {
        return FileResult {
            path: display,
            size,
            mtime_ns,
            findings,
        };
    }

    if let Ok(content) = fs::read_to_string(path) {
        let rules = &rules::COMPILED;
        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            for rule in rules.iter() {
                check_line(rule, line_no, line, &display, &mut findings);
            }
        }
        // 按 严重程度降序、行号升序 排序
        findings.sort_by(|a, b| {
            b.severity
                .rank()
                .cmp(&a.severity.rank())
                .then(a.line.cmp(&b.line))
        });
    }

    FileResult {
        path: display,
        size,
        mtime_ns,
        findings,
    }
}

/// 扫描入口：并行 + 增量缓存
pub fn scan_roots(roots: &[PathBuf], no_cache: bool) -> (Vec<Finding>, usize, usize, u64) {
    // 1. 收集文件
    let mut files: Vec<PathBuf> = Vec::new();
    for root in roots {
        let _ = collect_files(root, &mut files);
    }
    let total_files = files.len();

    // 2. 加载缓存
    let mut cache = load_cache();
    let mut hits = 0usize;

    // 3. 并行扫描（自动复用 CPU 核数）
    let results: Vec<(String, FileResult, bool)> = files
        .par_iter()
        .map(|path| {
            let abs_key = path.to_string_lossy().to_string();
            if !no_cache {
                if let Ok(md) = fs::metadata(path) {
                    let size = md.len();
                    let mtime = md
                        .modified()
                        .unwrap_or(UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos() as i128)
                        .unwrap_or(0);
                    if let Some(cached) = cache.entries.get(&abs_key) {
                        if cached.size == size && cached.mtime_ns == mtime {
                            return (abs_key, cached.clone(), true);
                        }
                    }
                }
            }
            // 找根目录做展示路径裁剪
            let root = roots
                .iter()
                .find(|r| path.starts_with(r))
                .map(|r| r.as_path())
                .unwrap_or_else(|| Path::new(""));
            (abs_key, scan_file(path, root), false)
        })
        .collect();

    // 4. 汇总 + 更新缓存
    let mut findings = Vec::new();
    let mut bytes = 0u64;
    for (abs_key, r, hit) in results {
        if hit {
            hits += 1;
        }
        if !no_cache {
            cache.entries.insert(abs_key, r.clone());
        }
        bytes += r.size;
        findings.extend(r.findings);
    }
    if !no_cache {
        cache.rules_hash = rules_fingerprint();
        cache.version = 1;
        save_cache(&cache);
    }

    // 最终排序
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });

    (findings, total_files, hits, bytes)
}

/// 当前 Unix 时间戳（秒）
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_detection() {
        assert!(is_placeholder("your-api-key"));
        assert!(is_placeholder("<token>"));
        assert!(is_placeholder("example_key"));
        assert!(!is_placeholder("sk-proj-AbCdEf1234567890"));
    }

    #[test]
    fn safe_url_domain() {
        assert!(is_safe_url_domain("https://github.com/foo/bar"));
        assert!(!is_safe_url_domain("https://webhook.site/abc"));
    }

    #[test]
    fn extract_secret_value_works() {
        assert_eq!(
            extract_secret_value(r#"password: "******""#),
            "******"
        );
        assert_eq!(
            extract_secret_value(r#"API_KEY = "sk-proj-AbCd1234""#),
            "sk-proj-AbCd1234"
        );
        assert_eq!(extract_secret_value("token = abcdef123456"), "abcdef123456");
        assert!(is_placeholder(&extract_secret_value(r#"password: "******""#)));
        assert!(!is_placeholder(&extract_secret_value(r#"key = "sk-proj-AbCd1234""#)));
    }
}
