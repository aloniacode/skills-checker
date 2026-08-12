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

/// 等级徽章：反色背景 + 固定宽度，视觉上一眼分级
fn sev_badge(sev: Severity) -> String {
    let label = sev.to_string().to_uppercase();
    let padded = format!(" {label:<8} ");
    match sev {
        Severity::Critical => padded.on_red().white().bold().to_string(),
        Severity::High => padded.on_bright_red().black().bold().to_string(),
        Severity::Medium => padded.on_yellow().black().to_string(),
        Severity::Low => padded.on_cyan().black().to_string(),
    }
}

/// 风险类型图标
fn type_icon(t: RiskType) -> &'static str {
    match t {
        RiskType::RemoteUpload => "📤",
        RiskType::HardcodedSecret => "🔑",
        RiskType::SuspiciousUrl => "🌐",
        RiskType::DangerousExec => "⚡",
    }
}

/// 终端彩色输出
pub fn render_terminal(result: &ScanResult, verbose: bool) {
    let clean = result.is_clean();
    let rule = "─".repeat(64);
    let rule_d = rule.dimmed();

    // 按文件分组（保持等级优先的原始顺序，组内不拆散）
    let mut groups: Vec<(&str, Vec<&crate::models::Finding>)> = Vec::new();
    for f in &result.findings {
        if let Some(entry) = groups.iter_mut().find(|(name, _)| *name == f.file) {
            entry.1.push(f);
        } else {
            groups.push((f.file.as_str(), vec![f]));
        }
    }

    // ---- 头部 ----
    if clean {
        println!();
        println!("  {}  {}  {}", "✅".green().bold(), "未发现安全风险".green().bold(), "全部配置干净".dimmed());
    } else {
        println!();
        println!(
            "  {} {} {} {}",
            "⚠️".yellow().bold(),
            format!("{}", result.findings.len()).red().bold().underline(),
            "处安全风险".bold(),
            format!("（涉及 {} 个文件）", groups.len()).dimmed(),
        );
        println!("{}", rule_d);
    }

    // ---- 风险明细（按文件分组，组内保持等级排序）----
    if !clean {
        for (idx, (file, findings)) in groups.iter().enumerate() {
            if idx > 0 {
                println!();
            }
            println!(
                "  {} {}  {}",
                "📄".bold(),
                file.bold().underline(),
                format!("{} 处风险", findings.len()).dimmed(),
            );
            for f in findings.iter() {
                println!(
                    "    {} {} {} {} {}",
                    format!("L{:<5}", f.line).dimmed(),
                    sev_badge(f.severity),
                    type_icon(f.risk_type),
                    f.risk_type,
                    format!("({})", f.rule_id).dimmed(),
                );
                println!("        {} {}", "→".dimmed(), f.description);
                if verbose {
                    println!("        {} {}", "代码:".cyan().dimmed(), f.snippet.dimmed());
                }
                println!("        {} {}", "修复:".green().bold(), f.fix);
            }
        }
    }

    // ---- 汇总面板 ----
    println!();
    println!("{}", rule_d);
    println!("  {} {}", "📊 扫描摘要".bold(), format!("(scanned_at {})", result.scanned_at).dimmed());
    println!(
        "    📂 根目录 {} 个 · 📄 文件 {} 个 · 💾 {:.1} MB · ⚡ {:.2}s · 🔁 缓存命中 {}",
        result.roots.len(),
        result.scanned_files,
        result.scanned_bytes as f64 / 1024.0 / 1024.0,
        result.duration_ms as f64 / 1000.0,
        result.cache_hits,
    );

    // 等级分布 + 类型分布（无风险时不展示空统计）
    if !clean {
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
        let total = result.findings.len().max(1);
        let bar = |n: usize| {
            if n == 0 {
                "▏".dimmed().to_string()
            } else {
                "█".repeat((n * 20 / total).max(1))
            }
        };
        println!(
            "    📊 等级分布  {} {}  {} {}  {} {}  {} {}",
            bar(crit).red().bold(),
            format!("{crit} critical").red().bold(),
            bar(high).bright_red(),
            format!("{high} high").bright_red(),
            bar(med).yellow(),
            format!("{med} medium").yellow(),
            bar(low).cyan(),
            format!("{low} low").cyan(),
        );

        // 类型分布
        let counts = type_counts(result);
        let parts: Vec<String> = counts
            .iter()
            .map(|(t, n)| format!("{} {} {}", type_icon(*t), t, format!("×{n}").dimmed()))
            .collect();
        println!("    🧩 类型分布  {}", parts.join("   "));
    }
    println!("{}", rule_d);
    println!();
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
