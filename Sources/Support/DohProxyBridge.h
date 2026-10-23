#ifndef DohProxyBridge_h
#define DohProxyBridge_h

/// fluxdo_doh（GPL-3.0）导出的 C 接口。
/// 它是一个本地 HTTP CONNECT 代理：DoH 解析 + ECH 加密 ClientHello + 可选 MITM。
/// 静态库由 CI 交叉编译产出（aarch64-apple-ios），见 .github/workflows。

/// 启动代理，config_json 为 ProxyConfig 的 JSON。返回监听端口，失败返回 -1。
int doh_proxy_start_with_config_json(const char *config_json);

/// 停止代理。
void doh_proxy_stop(void);

/// 是否正在运行（1/0）。
int doh_proxy_is_running(void);

/// 当前监听端口，未运行返回 -1。
int doh_proxy_get_port(void);

/// 新建一份 CA，返回 JSON：{"ok":true,"cert_pem":"...","key_pem":"..."}。
/// 调用方需用 doh_proxy_free_string 释放。
/// 取编译进库里的内置 CA 证书（PEM）。MITM 叶证书都由它签发。
/// 调用方需用 doh_proxy_free_string 释放。
char *doh_proxy_get_embedded_ca_pem(void);
char *doh_proxy_generate_ca(void);

/// 按域名签发 MITM 叶证书，返回 JSON：{"ok":true,"pem":"..."}。
char *doh_proxy_mitm_leaf_pem(const char *host);

/// 释放上面这些函数返回的字符串。
void doh_proxy_free_string(char *ptr);

/// 初始化日志。
void doh_proxy_init_logging(void);

#endif /* DohProxyBridge_h */
