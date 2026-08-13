//! 报告输出：终端彩色显示、JSON 导出、纯文本导出

use crate::models::{Finding, RiskType, ScanResult, Severity};
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

/// 按文件分组（保持等级优先的原始顺序，组内不拆散）
fn group_by_file<'a>(result: &'a ScanResult) -> Vec<(&'a str, Vec<&'a Finding>)> {
    let mut groups: Vec<(&str, Vec<&Finding>)> = Vec::new();
    for f in &result.findings {
        if let Some(entry) = groups.iter_mut().find(|(name, _)| *name == f.file) {
            entry.1.push(f);
        } else {
            groups.push((f.file.as_str(), vec![f]));
        }
    }
    groups
}

/// HTML 转义（防注入/格式破坏）
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

    let groups = group_by_file(result);

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

/// 写出报告文件（JSON / HTML / 文本），返回文件路径
pub fn export_to_file(result: &ScanResult, path: &str, format: &str) -> Result<(), String> {
    let text = match format {
        "json" => serde_json::to_string_pretty(result).map_err(|e| e.to_string())?,
        "html" => render_html(result),
        "text" => render_text(result),
        other => return Err(format!("不支持的导出格式: {other}（可选 json/html/text）")),
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

/// 生成自包含 HTML 报告（内联 CSS/JS，无外部依赖，含等级过滤）
pub fn render_html(result: &ScanResult) -> String {
    let clean = result.is_clean();
    let groups = group_by_file(result);

    // 统计
    let count = |sev: Severity| {
        result
            .findings
            .iter()
            .filter(|f| f.severity == sev)
            .count()
    };
    let crit = count(Severity::Critical);
    let high = count(Severity::High);
    let med = count(Severity::Medium);
    let low = count(Severity::Low);

    let sev_class = |s: Severity| match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    };

    // 头部状态
    let status_html = if clean {
        format!(
            r#"<div class="status ok"><span class="status-icon">✅</span>未发现安全风险 · 全部配置干净</div>"#
        )
    } else {
        format!(
            r#"<div class="status bad"><span class="status-icon">⚠️</span>发现 <b>{}</b> 处安全风险（涉及 {} 个文件）</div>"#,
            result.findings.len(),
            groups.len()
        )
    };

    // 等级过滤按钮（仅在有风险时显示）
    let filter_html = if clean {
        String::new()
    } else {
        r#"<div class="filters" id="filters">
            <button class="active" data-sev="all">全部</button>
            <button data-sev="critical">CRITICAL <span id="n-critical"></span></button>
            <button data-sev="high">HIGH <span id="n-high"></span></button>
            <button data-sev="medium">MEDIUM <span id="n-medium"></span></button>
            <button data-sev="low">LOW <span id="n-low"></span></button>
        </div>"#
        .to_string()
    };

    // 风险明细
    let mut findings_html = String::new();
    if !clean {
        for (file, findings) in &groups {
            findings_html.push_str(&format!(
                r#"<section class="file-group"><h2>📄 {} <span class="count">{}</span></h2>"#,
                escape_html(file),
                format!("{} 处风险", findings.len())
            ));
            for f in findings.iter() {
                let code_block = if f.snippet.is_empty() {
                    String::new()
                } else {
                    format!(r#"<pre class="code">{}</pre>"#, escape_html(&f.snippet))
                };
                findings_html.push_str(&format!(
                    r#"<div class="finding" data-sev="{}">
                        <div class="meta">
                            <span class="badge {}">{}</span>
                            <span class="line">L{}</span>
                            <span class="type">{} {}</span>
                            <span class="rule">{}</span>
                        </div>
                        <p class="desc">{}</p>
                        {}
                        <p class="fix"><b>修复:</b> {}</p>
                    </div>"#,
                    sev_class(f.severity),
                    sev_class(f.severity),
                    f.severity.to_string().to_uppercase(),
                    f.line,
                    type_icon(f.risk_type),
                    escape_html(&f.risk_type.to_string()),
                    f.rule_id,
                    escape_html(&f.description),
                    code_block,
                    escape_html(&f.fix),
                ));
            }
            findings_html.push_str("</section>");
        }
    } else {
        findings_html.push_str(r#"<div class="clean-note">本次扫描未发现任何安全风险。</div>"#);
    }

    // 类型分布
    let types_html = if clean {
        String::new()
    } else {
        let counts = type_counts(result);
        let parts: Vec<String> = counts
            .iter()
            .map(|(t, n)| {
                format!(
                    r#"<span class="type-chip">{} {} <b>×{}</b></span>"#,
                    type_icon(*t),
                    escape_html(&t.to_string()),
                    n
                )
            })
            .collect();
        format!(
            r#"<div class="stat-row"><span class="stat-label">🧩 类型分布</span><div class="chips">{}</div></div>"#,
            parts.join("")
        )
    };

    // 等级分布条
    let total = result.findings.len().max(1);
    let bar_html = |n: usize, sev: Severity| {
        let pct = n as f64 / total as f64 * 100.0;
        format!(
            r#"<div class="bar-seg {}" style="width:{:.1}%"><span>{}</span></div>"#,
            sev_class(sev),
            pct,
            n
        )
    };
    let dist_html = if clean {
        String::new()
    } else {
        format!(
            r#"<div class="stat-row"><span class="stat-label">📊 等级分布</span><div class="bar">{}{}{}{}<div class="bar-legend">
                <span class="critical">● {crit} critical</span>
                <span class="high">● {high} high</span>
                <span class="medium">● {med} medium</span>
                <span class="low">● {low} low</span>
            </div></div></div>"#,
            bar_html(crit, Severity::Critical),
            bar_html(high, Severity::High),
            bar_html(med, Severity::Medium),
            bar_html(low, Severity::Low),
        )
    };

    let scan_info = format!(
        r#"<div class="stat-row"><span class="stat-label">🔍 扫描信息</span><span class="stat-value">根目录 {} 个 · 文件 {} 个 · {:.1} MB · 耗时 {:.2}s · 缓存命中 {}</span></div>"#,
        result.roots.len(),
        result.scanned_files,
        result.scanned_bytes as f64 / 1024.0 / 1024.0,
        result.duration_ms as f64 / 1000.0,
        result.cache_hits
    );

    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>skills-checker 安全扫描报告</title>
<style>
  :root {{
    --bg: #f6f7f9; --card: #ffffff; --text: #1f2328; --muted: #6e7781;
    --border: #e1e4e8; --critical: #dc2626; --high: #ea580c;
    --medium: #ca8a04; --low: #2563eb;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font: 14px/1.7 -apple-system, "Segoe UI", "Microsoft YaHei", "PingFang SC", sans-serif; padding: 24px; }}
  .wrap {{ max-width: 960px; margin: 0 auto; }}
  header {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }}
  header h1 {{ font-size: 20px; }}
  header .time {{ color: var(--muted); font-size: 12px; }}
  .status {{ padding: 14px 18px; border-radius: 10px; font-size: 16px; margin-bottom: 16px; }}
  .status.ok {{ background: #ecfdf5; border: 1px solid #a7f3d0; color: #047857; }}
  .status.bad {{ background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c; }}
  .status-icon {{ margin-right: 8px; }}
  .filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }}
  .filters button {{ border: 1px solid var(--border); background: var(--card); color: var(--text); padding: 5px 12px; border-radius: 999px; cursor: pointer; font-size: 13px; }}
  .filters button.active {{ background: #0d1117; color: #fff; border-color: #0d1117; }}
  .file-group {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; margin-bottom: 14px; }}
  .file-group h2 {{ font-size: 15px; margin-bottom: 12px; word-break: break-all; }}
  .file-group h2 .count {{ color: var(--muted); font-weight: normal; font-size: 12px; margin-left: 8px; }}
  .finding {{ padding: 10px 12px; border-left: 3px solid var(--border); margin-bottom: 10px; background: #fafbfc; border-radius: 0 8px 8px 0; }}
  .finding[data-sev="critical"] {{ border-left-color: var(--critical); }}
  .finding[data-sev="high"] {{ border-left-color: var(--high); }}
  .finding[data-sev="medium"] {{ border-left-color: var(--medium); }}
  .finding[data-sev="low"] {{ border-left-color: var(--low); }}
  .finding.hidden {{ display: none; }}
  .meta {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; letter-spacing: .5px; }}
  .badge.critical {{ background: var(--critical); }}
  .badge.high {{ background: var(--high); }}
  .badge.medium {{ background: var(--medium); }}
  .badge.low {{ background: var(--low); }}
  .line {{ color: var(--muted); font-family: ui-monospace, Consolas, monospace; font-size: 12px; }}
  .type {{ font-weight: 600; }}
  .rule {{ color: var(--muted); font-size: 12px; margin-left: auto; font-family: ui-monospace, Consolas, monospace; }}
  .desc {{ margin: 4px 0; }}
  .code {{ background: #0d1117; color: #e6edf3; padding: 8px 12px; border-radius: 6px; font: 12px/1.6 ui-monospace, Consolas, monospace; margin: 6px 0; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .fix {{ color: #166534; background: #f0fdf4; padding: 6px 10px; border-radius: 6px; margin-top: 6px; font-size: 13px; }}
  .summary {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }}
  .stat-row {{ display: flex; gap: 12px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }}
  .stat-label {{ font-weight: 600; min-width: 90px; }}
  .bar {{ display: flex; height: 18px; border-radius: 6px; overflow: hidden; flex: 1; min-width: 200px; background: var(--border); }}
  .bar-seg {{ display: flex; align-items: center; justify-content: center; color: #fff; font-size: 11px; font-weight: 700; min-width: 22px; }}
  .bar-seg.critical {{ background: var(--critical); }}
  .bar-seg.high {{ background: var(--high); }}
  .bar-seg.medium {{ background: var(--medium); }}
  .bar-seg.low {{ background: var(--low); }}
  .bar-legend {{ display: flex; gap: 14px; font-size: 12px; width: 100%; color: var(--muted); }}
  .chips {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .type-chip {{ background: #eef2f7; border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; font-size: 12px; }}
  .clean-note {{ color: var(--muted); padding: 20px; text-align: center; }}
  footer {{ color: var(--muted); font-size: 12px; text-align: center; margin-top: 20px; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #0d1117; --card: #161b22; --text: #e6edf3; --muted: #8b949e; --border: #30363d; }}
    .status.ok {{ background: #0f2e22; border-color: #1b5e3f; color: #7ee2a8; }}
    .status.bad {{ background: #331c1c; border-color: #7f1d1d; color: #fca5a5; }}
    .finding {{ background: #0d1117; }}
    .fix {{ color: #7ee2a8; background: #10231a; }}
    .type-chip {{ background: #21262d; }}
    .filters button {{ background: #21262d; border-color: #30363d; color: #e6edf3; }}
    .filters button.active {{ background: #f0f6fc; color: #0d1117; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🔍 skills-checker 安全扫描报告</h1>
    <span class="time">扫描时间: {scanned_at} · 工具 v{version}</span>
  </header>
  {status}
  {filters}
  {findings}
  <section class="summary">
    {scan_info}
    {dist}
    {types}
  </section>
  <footer>由 skills-checker 生成 · 退出码参考: 0=无风险 1=发现风险 2=运行错误</footer>
</div>
<script>
  (function () {{
    const counts = {{ critical: {crit}, high: {high}, medium: {med}, low: {low} }};
    for (const [k, v] of Object.entries(counts)) {{
      const el = document.getElementById('n-' + k);
      if (el) el.textContent = v;
    }}
    const buttons = document.querySelectorAll('#filters button');
    buttons.forEach(btn => btn.addEventListener('click', () => {{
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const sev = btn.dataset.sev;
      document.querySelectorAll('.finding').forEach(f => {{
        f.classList.toggle('hidden', sev !== 'all' && f.dataset.sev !== sev);
      }});
    }}));
  }})();
</script>
</body>
</html>"#,
        scanned_at = result.scanned_at,
        version = env!("CARGO_PKG_VERSION"),
        status = status_html,
        filters = filter_html,
        findings = findings_html,
        scan_info = scan_info,
        dist = dist_html,
        types = types_html,
    )
}
