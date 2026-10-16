#!/bin/sh
# 打 iPhone / iPad 的包：编成 WASM 组件（wasm32-wasip2），把它与清单放进 dist/stage-ios，用 hhh-im-pack 打成 .hhhim 并写进版本索引
# （与电脑的包同一份，同一版本会合并）。HHH 的 iOS 版在 App 里跑这个组件。
# 用法：WASI_SDK_PATH=<wasi-sdk 目录> scripts/pack-ios.sh [--publish] [--sign-key <私钥文件>]（参数原样交给 hhh-im-pack）
#   ring 有 C 代码，要能出 wasm 的 clang：装 wasi-sdk（https://github.com/WebAssembly/wasi-sdk），WASI_SDK_PATH 指到它。
#   第一次先装目标：rustup target add wasm32-wasip2。
#   tokio 在 WASI 上的网络与文件只在 tokio_unstable 下开放，这里自动带上。
# hhh-im-pack 要 v0.6.0 起（认得 wasm32-wasip2）：cargo install --git https://github.com/MagicLizi/hhh-im-sdk --tag v0.6.0 hhh-im-protocol --features transport,package
set -eu
cd "$(dirname "$0")/.."
: "${WASI_SDK_PATH:?先把 WASI_SDK_PATH 设成 wasi-sdk 的目录}"
# cc 会按空格拆开 CC：路径带空格时经一个不带空格的软链接给出。
sdk="$WASI_SDK_PATH"
case "$sdk" in
    *" "*)
        link="${TMPDIR:-/tmp}/friend-im-wasi-sdk"
        ln -sfn "$sdk" "$link"
        sdk="$link"
        ;;
esac
export CC_wasm32_wasip2="$sdk/bin/clang"
export AR_wasm32_wasip2="$sdk/bin/llvm-ar"
export CFLAGS_wasm32_wasip2="--sysroot=$sdk/share/wasi-sysroot"
export CARGO_TARGET_WASM32_WASIP2_RUSTFLAGS="--cfg tokio_unstable"
cargo build --release --target wasm32-wasip2 --bin friend-im
rm -rf dist/stage-ios
mkdir -p dist/stage-ios
cp hhh-im-provider.json logo.svg dist/stage-ios/
cp target/wasm32-wasip2/release/friend-im.wasm dist/stage-ios/
hhh-im-pack dist/stage-ios --target wasm32-wasip2 --out dist --notes notes.md "$@"
