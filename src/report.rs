//! 报告输出：终端彩色显示、JSON 导出、纯文本导出

use crate::models::{RiskType, ScanResult, Severity};
use colored::Colorize;
use std::io::Write;

/// 按风险类型分组统计
fn type_counts(result: &ScanResult) -> Vec<(RiskType, usize)> {
    let mut counts: Vec<(RiskType, usize)> = vec![];
    for f in &result.findings {
        if let Some(e) = counts.iter_mut().find(|(t, _)| *t == f.risk_type) {
            e.1 += 1;
        } else {
            counts.push((f.risk_type, 1));
        }
    }
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    counts
}

fn sev_label(sev: Severity) -> String {
    match sev {
        Severity::Critical => "CRITICAL".red().bold().to_string(),
        Severity::High => "HIGH".red().to_string(),
        Severity::Medium => "MEDIUM".yellow().to_string(),
        Severity::Low => "LOW".cyan().to_string(),
    }
}

/// 终端彩色输出
pub fn render_terminal(result: &ScanResult, verbose: bool) {
    let clean = result.is_clean();

    if clean {
        println!("{} 未发现安全风险。", "✅".green().bold());
    } else {
        println!(
            "{} 发现 {} 处安全风险：",
            "⚠️".yellow().bold(),
            result.findings.len()
        );
        println!();

        let mut current_file: Option<&str> = None;
        for f in &result.findings {
            if current_file != Some(f.file.as_str()) {
                current_file = Some(f.file.as_str());
                println!("{}", format!("📄 {}", f.file).bold().underline());
            }
            println!(
                "  {} [{}] {} · {}",
                format!("L{}", f.line).dimmed(),
                sev_label(f.severity),
                f.risk_type.to_string().bold(),
                format!("({})", f.rule_id).dimmed(),
            );
            println!("      {} {}", "→".dimmed(), f.description);
            if verbose {
                println!("      {} {}", "代码:".dimmed(), f.snippet);
            }
            println!("      {} {}", "修复:".green().dimmed(), f.fix);
        }
    }

    println!();
    println!(
        "{} 扫描根目录 {} 个 | 文件 {} 个 | 读取 {:.1} MB | 缓存命中 {} | 耗时 {:.2}s",
        "🔍".bold(),
        result.roots.len(),
        result.scanned_files,
        result.scanned_bytes as f64 / 1024.0 / 1024.0,
        result.cache_hits,
        result.duration_ms as f64 / 1000.0,
    );

    // 分等级统计
    let crit = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let med = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = result
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    println!(
        "{}  等级分布: {} critical · {} high · {} medium · {} low",
        "📊".bold(),
        format!("{crit}").red().bold(),
        format!("{high}").red(),
        format!("{med}").yellow(),
        format!("{low}").cyan(),
    );

    // 风险类型分布
    if !clean {
        let counts = type_counts(result);
        let parts: Vec<String> = counts.iter().map(|(t, n)| format!("{}×{}", t, n)).collect();
        println!("{}  类型分布: {}", "🧩".bold(), parts.join(" · "));
    }
}

/// 纯文本输出（无颜色，适合落盘）
pub fn render_text(result: &ScanResult) -> String {
    let mut buf = String::new();
    buf.push_str(&format!(
        "skills-checker 扫描报告 ({} 个根目录, {} 文件, {} 风险)\n",
        result.roots.len(),
        result.scanned_files,
        result.findings.len()
    ));
    buf.push_str(&format!(
        "扫描时间: {} | 耗时: {:.2}s | 缓存命中: {}\n\n",
        result.scanned_at,
        result.duration_ms as f64 / 1000.0,
        result.cache_hits
    ));
    for f in &result.findings {
        buf.push_str(&format!(
            "[{}] {}:{} [{}] {} ({})\n",
            f.severity.to_string().to_uppercase(),
            f.file,
            f.line,
            f.risk_type,
            f.description,
            f.rule_id
        ));
        buf.push_str(&format!("  代码: {}\n", f.snippet));
        buf.push_str(&format!("  修复: {}\n\n", f.fix));
    }
    buf.push_str(&format!(
        "结论: {}\n",
        if result.is_clean() {
            "未发现风险".to_string()
        } else {
            format!("发现 {} 处风险", result.findings.len())
        }
    ));
    buf
}

/// 写出报告文件（JSON 或文本），返回文件路径
pub fn export_to_file(result: &ScanResult, path: &str, format: &str) -> Result<(), String> {
    let text = match format {
        "json" => serde_json::to_string_pretty(result).map_err(|e| e.to_string())?,
        "text" => render_text(result),
        other => return Err(format!("不支持的导出格式: {other}（可选 json/text）")),
    };
    std::fs::write(path, text).map_err(|e| format!("写入 {} 失败: {e}", path))?;
    Ok(())
}

/// 将 JSON 输出到 stdout
pub fn render_json(result: &ScanResult) {
    match serde_json::to_string_pretty(result) {
        Ok(s) => {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(s.as_bytes());
            let _ = out.write_all(b"\n");
        }
        Err(e) => eprintln!("JSON 序列化失败: {e}"),
    }
}
