# phantom-research

基于 [phantom-http](https://github.com/bywayhq/phantom) 的浏览器 TLS/HTTP 指纹研究工具。

可以在不使用无头浏览器的情况下，通过 BoringSSL + JSON 配置文件精确模拟 Chrome 系浏览器（Chrome、Brave、Edge 等）的网络层指纹。

## 原理

现代 anti-bot 系统通过多个层级识别客户端身份：

```
TLS 层     →  ClientHello 指纹（JA3/JA4）
HTTP/2 层  →  SETTINGS 帧 + WINDOW_UPDATE（Akamai fingerprint）
HTTP 层    →  Header 顺序、Sec-CH-UA、Sec-Fetch-* 等
```

Phantom 使用 BoringSSL（Chrome 的 TLS 库）发起请求，通过可编辑的 JSON profile 控制每一层的参数，使流量在指纹层面与真实浏览器完全一致。

## 验证结果

以 Brave 157 on Windows 为目标，与真实浏览器的指纹对比：

| 指标 | 模拟值 | 真实 Brave | 是否一致 |
|------|--------|------------|----------|
| JA4 | `t13d1516h2_8daaf6152771_806a8c22fdea` | 同左 | ✅ |
| JA4_r (sorted extensions) | 完整匹配 | — | ✅ |
| Peetprint | 完整匹配 | — | ✅ |
| Akamai HTTP/2 hash | `52d84b11737d980aef856699f885ca86` | 同左 | ✅ |
| TLS extension count | 16 (non-GREASE) | 16 | ✅ |
| HTTP/2 SETTINGS | `1:65536;2:0;4:6291456;6:262144` | 同左 | ✅ |
| WINDOW_UPDATE | `15663105` | 同左 | ✅ |
| Pseudo-header 顺序 | `m,a,s,p` | 同左 | ✅ |

## 快速开始

### 方式一：下载预编译二进制

从 [GitHub Actions](../../actions) 的最新成功构建中下载 artifacts（Windows / Linux）。

### 方式二：从源码编译

**构建依赖**（仅编译时需要，运行时不需要）：
- Rust 1.88+（推荐 stable 最新版）
- CMake
- Clang / LLVM（需要 libclang）
- NASM
- C++ 编译器（Windows 需要 MSVC + Windows SDK）

```bash
cargo build --release
```

首次编译约 8-10 分钟（需要编译 BoringSSL），后续增量编译很快。

## 使用方法

### 1. 直接运行测试工具

```bash
./phantom-research          # Linux
phantom-research.exe        # Windows
```

程序会：
1. 导出 Chrome 156 的 profile → JSON
2. 修补 TLS 配置使其匹配 Brave（移除 trust_anchors 扩展）
3. 用 Brave 的 header 发起请求到 `tls.peet.ws/api/all`
4. 输出指纹对比结果

### 2. 在自己的 Rust 项目中使用 Phantom

```toml
# Cargo.toml
[dependencies]
phantom = { package = "phantom-http", version = "0.6", features = ["full"] }
tokio = { version = "1", features = ["macros", "rt", "net", "time"] }
serde_json = "1"
```

### 3. 使用内置 profile 发请求

```rust
use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::Client;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 选择 Chrome 156 Windows 的导航请求 profile
    let profile = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
    let client = Client::builder(profile).build()?;

    let response = client.get("https://example.com/")?.send().await?;
    println!("Status: {}", response.status());
    let body = response.into_body().collect_with_limit(1 << 20).await?;
    println!("{} bytes", body.len());
    Ok(())
}
```

可用的内置 profile：
- `chrome-156-windows` / `chrome-156-linux` / `chrome-156-macos`
- `chrome-154-windows` / `chrome-154-macos` / `chrome-154-android`
- `firefox-157-windows`
- 更多参见 Phantom 文档

可用的请求模板（`RequestTemplateKind`）：
- `Navigation` — 地址栏导航（默认）
- `Fetch` — JS fetch() GET 请求
- `FetchNoStore` — cache: "no-store" 的 fetch
- `FetchUpload` — fetch() POST
- `Script` / `Stylesheet` / `Image` / `Font` — 子资源加载

### 4. 导出 → 修改 → 导入 profile（核心用法）

这是实现"一个二进制 + 多个 JSON 配置"架构的关键：

```rust
use phantom::fingerprint;
use phantom::profile::catalog::{profile_for, RequestTemplateKind};
use phantom::Client;

// 第一步：导出基础 profile 为 JSON
let base = profile_for("chrome-156-windows", RequestTemplateKind::Navigation)?;
let json_bytes = fingerprint::export_profile_json(&base)?;
let mut value: serde_json::Value = serde_json::from_slice(&json_bytes)?;

// 第二步：修改 TLS 配置
// 例：移除 trust_anchors 扩展（Brave 不发送这个扩展）
if let Some(tai) = value.pointer_mut("/profile/tls/requested_trust_anchor_ids") {
    *tai = serde_json::Value::Null;
}

// 第三步：导入修改后的 profile
let patched_bytes = serde_json::to_vec(&value)?;
let brave_profile = fingerprint::import_profile_json(&patched_bytes)?;

// 第四步：用修改后的 profile 发请求
let client = Client::builder(brave_profile).build()?;
let resp = client.get("https://example.com/")?.send().await?;
```

修改后的 JSON 可以保存到文件，运行时直接加载，无需重新编译：

```rust
// 保存
std::fs::write("profiles/brave-157-windows.json",
    serde_json::to_string_pretty(&value)?)?;

// 加载（运行时，不需要重编译）
let json = std::fs::read("profiles/brave-157-windows.json")?;
let profile = fingerprint::import_profile_json(&json)?;
let client = Client::builder(profile).build()?;
```

### 5. 覆盖请求 Header

Profile 控制 TLS 和 HTTP/2 层的指纹，Header 差异通过 `RequestHeader` 覆盖：

```rust
use phantom::RequestHeader;

let response = client
    .get("https://example.com/")?
    // Brave 的 brand 标识
    .header(RequestHeader::new(
        "sec-ch-ua",
        "\"Not-A.Brand\";v=\"99\", \"Brave\";v=\"157\", \"Chromium\";v=\"157\""))
    // Brave 的 User-Agent（版本号可能不同）
    .header(RequestHeader::new(
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"))
    // Brave 移除了 signed-exchange
    .header(RequestHeader::new(
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8"))
    // Brave 的 Global Privacy Control
    .header(RequestHeader::new("sec-gpc", "1"))
    // Brave 的 accept-language quality 值
    .header(RequestHeader::new("accept-language", "en-US,en;q=0.8"))
    .send()
    .await?;
```

### 6. 按请求类型切换模板

真实浏览器对不同资源类型发送不同的 header 集合：

```rust
use phantom::profile::catalog::RequestTemplateKind;

// 先做导航请求（页面加载）
let page = client.get("https://example.com/")?.send().await?;

// 然后用 Fetch 模板请求 API（共享同一个 TLS 连接）
let api = client
    .get("https://example.com/api/data")?
    .context(RequestTemplateKind::Fetch)?
    .header(RequestHeader::new("referer", "https://example.com/"))
    .send()
    .await?;
```

## Profile JSON 结构

导出的 JSON 包含完整的连接配置，每个字段都可编辑：

```
{
  "format": "phantom.custom-profile",
  "version": 2,
  "profile": {
    "tls": {
      "cipher_suites": [...],              // Cipher suite 列表和顺序
      "groups": [...],                      // Supported groups (curves)
      "key_shares": [...],                  // Key share entries
      "signature_schemes": [...],           // Signature algorithms
      "extension_order": { "kind": "Permuted" },  // Chrome 式扩展随机排列
      "grease": true,                       // GREASE 启用
      "ech": { ... },                       // Encrypted Client Hello
      "certificate_compression": ["Brotli"],
      "requested_trust_anchor_ids": null,   // null = 不发送此扩展
      "versions": { "min": "Tls12", "max": "Tls13" },
      ...
    },
    "http2": { ... },         // HTTP/2 SETTINGS, WINDOW_UPDATE 等
    "http3": { ... },         // HTTP/3 / QUIC 配置
    "tcp": { ... },           // TCP 层参数
    "client_hints": { ... },  // Sec-CH-UA 等 Client Hints
    "request_template": { ... },  // 默认请求模板
    "request_contexts": { ... },  // 按请求类型的模板集合
    ...
  }
}
```

### 模拟不同浏览器的关键差异点

| 从 Chrome → Brave | 修改方式 |
|-------------------|----------|
| 移除 trust_anchors 扩展 | JSON: `requested_trust_anchor_ids` → `null` |
| Sec-CH-UA brand | Header 覆盖 |
| 添加 sec-gpc: 1 | Header 覆盖 |
| accept 去掉 signed-exchange | Header 覆盖 |
| accept-language quality | Header 覆盖 |

| 从 Chrome → Edge | 修改方式 |
|-------------------|----------|
| Sec-CH-UA brand 改为 Edge | Header 覆盖 |
| 可能有不同的 trust_anchors 配置 | JSON 修改 |

## 关于版本跨度

TLS 和 HTTP/2 的传输指纹在 Chrome 小版本之间基本不变。Chrome 156 的 profile 可以用于模拟 155-158 范围内的任何 Chromium 系浏览器，只需要通过 Header 覆盖调整版本号。

需要关注新 profile 的时机：
- Chromium 新增/移除 cipher suite
- 新增 TLS 扩展（如 trust_anchors 是 Chrome 141 引入的）
- HTTP/2 SETTINGS 值变更
- 新增后量子算法支持

## 指纹验证方法

用 `tls.peet.ws/api/all` 检查你的 TLS 和 HTTP/2 指纹，拿真实浏览器访问同一个 URL 的结果做对比。重点关注：

- `tls.ja4` / `tls.ja4_r` — TLS 指纹（扩展排序后的哈希）
- `tls.peetprint` — 完整的 TLS 特征描述
- `http2.akamai_fingerprint_hash` — HTTP/2 帧指纹
- `http2.sent_frames` — SETTINGS / WINDOW_UPDATE / HEADERS 的具体值

## 许可

本研究工具仅用于网络协议分析和安全研究。请遵守目标服务的使用条款。
