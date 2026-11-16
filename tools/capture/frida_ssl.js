/*
 * SSL Pinning Bypass
 *
 * 用法:
 *   frida -U -f com.example.app -l frida_ssl.js --no-pause
 *
 * 覆盖常见的证书固定实现:
 *   1. TrustManager 全家桶
 *   2. OkHttp CertificatePinner
 *   3. HostnameVerifier
 *   4. 常见网络库（Volley / HttpsURLConnection）
 *
 * 只绕过「校验证书」这一步，不改业务数据，通常也不会触发完整性自校验。
 */

var TAG = "[ssl-bypass]";

function log(s) {
    console.log(TAG + " " + s);
}

Java.perform(function () {
    // ── 1. TrustManager ──
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.recon.TrustAll",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var ctx = SSLContext.getInstance("TLS");
        ctx.init(null, TrustManagers, null);
        SSLContext.getInstance.overload("java.lang.String").implementation = function (proto) {
            log("SSLContext.getInstance(" + proto + ") -> trust-all");
            var real = this.getInstance(proto);
            try { real.init(null, TrustManagers, null); } catch (e) {}
            return real;
        };
        log("OK: SSLContext hooked");
    } catch (e) {
        log("FAIL SSLContext: " + e.message);
    }

    // ── 2. OkHttp CertificatePinner ──
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
            log("CertificatePinner.check bypassed");
        };
        try {
            CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function () {
                log("CertificatePinner.check$okhttp bypassed");
            };
        } catch (e2) { /* 版本差异 */ }
        log("OK: CertificatePinner hooked");
    } catch (e) {
        log("FAIL CertificatePinner: " + e.message);
    }

    // ── 3. HostnameVerifier ──
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var HV = Java.registerClass({
            name: "com.recon.AnyHost",
            implements: [HostnameVerifier],
            methods: {
                verify: function () { return true; }
            }
        });
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier(HV.$new());
        HttpsURLConnection.setHostnameVerifier.implementation = function () { /* noop */ };
        log("OK: HostnameVerifier hooked");
    } catch (e) {
        log("FAIL HostnameVerifier: " + e.message);
    }

    // ── 4. 原生层：部分加固在 native 做 pinning ──
    try {
        var SSL_VERIFY = Module.findExportByName("libssl.so", "SSL_get_verify_result");
        if (SSL_VERIFY) {
            Interceptor.attach(SSL_VERIFY, {
                onLeave: function (retval) {
                    retval.replace(0); // X509_V_OK
                }
            });
            log("OK: native SSL_get_verify_result hooked");
        }
    } catch (e) {
        log("FAIL native ssl: " + e.message);
    }

    log("bypass armed");
});
