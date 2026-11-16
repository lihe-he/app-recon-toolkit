/*
 * hook OkHttp —— 打印请求体与响应体
 *
 * 用法:
 *   frida -U -f com.example.app -l frida_okhttp.js --no-pause
 *   frida -U -n 目标进程 -l frida_okhttp.js
 *
 * 说明:
 *   只 hook 打印，不修改任何数据，不会触发完整性校验。
 *   如果目标有反调试，先用 frida_ssl.js 的思路处理，或者改用 gadget 注入。
 */

var TAG = "[okhttp]";

function log(s) {
    console.log(TAG + " " + s);
}

function toStr(bytes) {
    if (!bytes) return "<null>";
    try {
        return Java.array('byte', bytes).toString();
    } catch (e) {
        return "<unconvertible>";
    }
}

Java.perform(function () {
    log("attaching...");

    try {
        var Buffer = Java.use("okio.Buffer");
        var Request = Java.use("okhttp3.Request");
        var Response = Java.use("okhttp3.Response");

        // 请求体
        Request.toString.overload().implementation = function () {
            var out = this.toString();
            var body = this.body();
            if (body != null) {
                try {
                    var buffer = Buffer.$new();
                    body.writeTo(buffer);
                    var text = buffer.readUtf8();
                    out += "\n    BODY: " + text;
                    out += "\n    CL: " + body.contentLength();
                } catch (e) {
                    out += "\n    BODY: <binary or stream>";
                }
            }
            log("REQ\n    " + out.replace(/\n/g, "\n    "));
            return out;
        };

        // 响应体
        Response.toString.overload().implementation = function () {
            var out = this.toString();
            try {
                var body = this.body();
                if (body != null && body.string() != null) {
                    var text = body.string();
                    out += "\n    BODY: " + text;
                }
            } catch (e) {
                out += "\n    BODY: <consumed>";
            }
            log("RESP\n    " + out.replace(/\n/g, "\n    "));
            return out;
        };

        log("hooked okhttp3.Request / Response");
    } catch (e) {
        log("okhttp3 not found: " + e.message);
    }

    // 老版本 HttpURLConnection 兜底
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var conn = this.openConnection();
            log("URL.openConnection: " + this.toString());
            return conn;
        };
    } catch (e) {
        /* 没有就算了 */
    }
});
