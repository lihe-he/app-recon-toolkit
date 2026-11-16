# app-recon-toolkit

Android 协议逆向工具链。**通用工具，不绑定任何具体 App。**

## 定位

这个仓库不是"某个 App 的破解脚本"，而是把一次真实逆向里用到的动作沉淀成可复用工具：

| 阶段 | 工具 | 解决什么 |
|---|---|---|
| 侦察 | `apk_scan` | 这个 APK 用了什么加固、有哪些检测库、集成了哪些 SDK |
| 定位 | `string_hunt` | 手里只有一句日志/错误信息，怎么定位到具体的 .so |
| 分析 | `elf_sym` | 拿到 .so 后，导出符号在哪、detect 函数长什么样、patch 点在哪 |
| 抓包 | `frida_okhttp.js` | 打印 OkHttp 请求体/响应体 |
| 抓包 | `frida_ssl.js` | 证书固定绕过 |
| 探测 | `fuzz_fields` | 用服务端的拒绝原因当 oracle，摸清校验规则 |
| 探测 | `rule_miner` | 从多次拒绝里自动归纳出规则 |

## 为什么这样做

运行时 hook（改内存、改返回值）在加固面前很脆弱：反调试、完整性自校验、动态代码校验，任何一层都能打死你。

更稳的路子是：

```
离线把协议摸清楚  →  写一个纯 HTTP 客户端  →  运行时完全不碰 APK
```

客户端检测（模拟器/root/frida）在这一步全部不参与，因为你根本没加载那个进程。

## 用法

```bash
pip install -e .

# 侦察一个 APK
recon-scan app.apk

# 手上只有一句日志 "E/lishang: start detect"，找它在哪个 so 里
recon-hunt lib/arm64-v8a/*.so --string "lishang" --string "start  detect"

# 找到后分析导出符号并反汇编
recon-elf libemulator_check.so --disasm Java_com_xxx_detect

# 抓包
frida -U -f com.example.app -l tools/capture/frida_okhttp.js
```

## 方法论

见 [docs/methodology.md](docs/methodology.md)。

## 许可

Apache-2.0。工具本身是中性的，怎么用取决于使用者。
