//! skills-checker — 本地 Agent/SKILL 配置安全检测工具
//!
//! 用法示例：
//!   skills-checker                       # 全局默认扫描常见 Agent 目录
//!   skills-checker -d ~/.claude          # 指定目录
//!   skills-checker -d ./skills --json    # JSON 输出到 stdout
//!   skills-checker -d ./skills -o out.json --format json
//!   skills-checker --fail-on high -q     # CI 集成：仅 high 及以上触发失败

mod models;
mod report;
mod rules;
mod scanner;

use clap::{ArgAction, Parser};
use models::{ScanResult, Severity};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "skills-checker",
    version,
    about = "扫描本地 Agent/SKILL 配置中的安全隐患（远程上传/硬编码密钥/可疑外联/危险命令）",
    after_help = "退出码: 0=无风险, 1=发现达到 --fail-on 阈值的风险, 2=运行错误"
)]
struct Args {
    /// 指定扫描目录（可多次指定）；缺省时扫描常见全局 Agent 配置目录
    #[arg(short = 'd', long = "path", value_name = "DIR", action = ArgAction::Append)]
    paths: Vec<PathBuf>,

    /// JSON 格式输出到 stdout
    #[arg(long)]
    json: bool,

    /// 导出报告到文件（结合 --format 决定格式）
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    /// 导出格式: auto | json | html | text（默认 auto，按输出文件扩展名推断）
    #[arg(long, value_name = "FORMAT", default_value = "auto")]
    format: String,

    /// 禁用增量缓存
    #[arg(long)]
    no_cache: bool,

    /// 安静模式：不打印风险明细
    #[arg(short = 'q', long)]
    quiet: bool,

    /// 详细模式：显示命中的代码片段
    #[arg(short = 'v', long)]
    verbose: bool,

    /// 触发退出码 1 的最低风险等级
    #[arg(long, value_name = "LEVEL", default_value = "low", value_parser = models::parse_severity)]
    fail_on: Severity,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // ---- 确定扫描根目录 ----
    let roots: Vec<PathBuf> = if !args.paths.is_empty() {
        let mut ok = Vec::new();
        for p in &args.paths {
            if p.is_dir() {
                ok.push(p.clone());
            } else {
                eprintln!("[warn] 目录不存在，已跳过: {}", p.display());
            }
        }
        if ok.is_empty() {
            eprintln!("错误: 未找到任何有效扫描目录。请使用 -d/--path 指定存在的目录。");
            return ExitCode::from(2);
        }
        ok
    } else {
        let dirs = scanner::default_search_dirs();
        if dirs.is_empty() {
            eprintln!("未发现常见的全局 Agent 配置目录。请使用 -d/--path 显式指定扫描目录。");
            return ExitCode::from(2);
        }
        dirs
    };

    // ---- 执行扫描 ----
    let start = Instant::now();
    let (findings, scanned_files, cache_hits, scanned_bytes) =
        scanner::scan_roots(&roots, args.no_cache);
    let duration_ms = start.elapsed().as_millis() as u64;

    let result = ScanResult {
        scanned_at: scanner::now_unix(),
        roots: roots.iter().map(|r| r.display().to_string()).collect(),
        scanned_files,
        scanned_bytes,
        cache_hits,
        duration_ms,
        findings,
    };

    // ---- 输出 ----
    if args.json {
        report::render_json(&result);
    } else if !args.quiet {
        report::render_terminal(&result, args.verbose);
    } else {
        // quiet：仅一行摘要
        println!(
            "scanned={} findings={} cache_hits={} duration_ms={}",
            scanned_files,
            result.findings.len(),
            cache_hits,
            duration_ms
        );
    }

    // ---- 导出文件 ----
    if let Some(out) = &args.output {
        let format = if args.format == "auto" {
            match std::path::Path::new(out)
                .extension()
                .and_then(|e| e.to_str())
            {
                Some("json") => "json",
                Some("html") | Some("htm") => "html",
                Some("txt") | Some("text") | Some("md") => "text",
                _ => "json",
            }
        } else {
            args.format.as_str()
        };
        match report::export_to_file(&result, out, format) {
            Ok(()) => {
                if !args.quiet {
                    println!("[ok] 报告已导出: {}（格式: {}）", out, format);
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    }

    // ---- 退出码 ----
    if result.count_ge(args.fail_on) > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
