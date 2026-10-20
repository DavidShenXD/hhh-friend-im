//! Cindy IM 插件程序（HHH-IM-Protocol v1）。
//!
//! 插件是一个子进程：HHH 从标准输入一行一条发 JSON-RPC 请求，插件从标准输出一行一条回；日志走 `log/write`
//! 通知，标准输出不写别的东西。请求循环与各个方法在库里（`friend_im::server`）。
//! `--version` 只打印版本就退出（手动核对装的是哪一版用）。

// Windows：按窗口程序编，桌面宿主拉起时不弹控制台窗口；标准输入输出照样走宿主接好的管道。
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if std::env::args().any(|arg| arg == "--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }
    #[cfg(not(target_os = "wasi"))]
    let built = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build();
    // WASI 构建（手机上由宿主解释执行）没有线程：单线程运行时。
    #[cfg(target_os = "wasi")]
    let built = tokio::runtime::Builder::new_current_thread().enable_all().build();
    let runtime = match built {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Cindy IM 插件的运行时建不起来：{error}");
            std::process::exit(1);
        }
    };
    runtime.block_on(friend_im::run_stdio());
    // 标准输入关了：还在跑的任务至多再等一秒（让最后几条回复写出去）。
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
}
