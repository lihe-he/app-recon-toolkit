# 方法论

这份文档记录「面对一个带服务端校验的 App，该怎么下手」的判断流程。
工具只是手段，先想清楚走哪条路。

---

## 一、先判断：运行时 hook 还是协议级

**问三个问题：**

1. App 有没有加固（尤其是有没有反调试 / 完整性自校验 / 动态代码校验）
2. 关键数据是**本地计算**还是**服务端判定**
3. 校验依赖的是**环境**还是**数据**

判断表：

| 情况 | 结论 |
|---|---|
| 数据在服务端判定（订单、运动记录、积分） | **协议级**。改本地毫无意义 |
| 只有客户端检测，数据本地生效（游戏内存、单机） | 运行时 hook 可行 |
| 有加固 + 动态代码校验 + 反调试 | **不要在运行时硬刚**，投入产出比极低 |
| 校验依赖传感器/摄像头/蓝牙等真实硬件 | 协议级也难过，考虑放弃 |

**真实的坑**：很多人一上来就 Frida，花几天跟反调试对抗，
最后发现就算 hook 成功，数据提交上去服务端照样拒——因为校验在云端。

---

## 二、定位：从一句日志到具体的库

逆向经常是从一个现象开始的：「点某个按钮就闪退，logcat 里只有一行日志」。

```bash
adb logcat -c && adb logcat | grep -iE 'detect|安全|risk|exit'
```

假设看到：

```
E lishang :  start  detect
I AndroidRuntime: System.exit called, status: 0
```

**关键信息**：tag 是 `lishang`，消息是 `start  detect`（注意两个空格，这是原文）。

下一步：这两个字符串在哪个文件里？

```bash
# 先 APK 侦察
recon-scan app.apk

# 再字节级定位（二进制文件不能 grep 文本）
recon-hunt lib/arm64-v8a/*.so --string "lishang" --string "start  detect"
```

命中 `libemulator_check.so`。

> **注意**：库名可能骗人。叫 `libemulator_check` 的库，实际做的可能是
> 「校验自己有没有被改」而不是「检测模拟器」。名字只是名字。

---

## 三、分析：符号 → 反汇编 → 找分支

```bash
recon-elf libemulator_check.so --disasm
```

输出会直接告诉你 JNI 入口：

```
[JNI 入口]
  0x00000c18  com.snail.antifake.jni.EmulatorDetectUtil.detect
```

同时看导入符号，一眼能看出这个库在干什么：

```
[导入的函数]
__android_log_print, sigaction, mmap, getpagesize, munmap, fopen, exit, __clear_cache
```

这组导入非常说明问题：
- `sigaction` + `exit` → 有可能自己处理崩溃信号
- `mmap` + `__clear_cache` → **在运行时生成并执行机器码**
- `fopen` → 读文件

反汇编确认：

```bash
recon-elf lib.so --disasm 0xc18 --len 0x240
```

关键片段：

```asm
mov  w0, #0xb            ; SIGSEGV
bl   sigaction           ; 注册信号处理器
...
blr  x8                 ; 执行 mmap 页里拷进去的代码
...
cmp  w8, #1
cset w0, eq             ; 返回 (结果 == 1)
ret
```

**结论**：这是动态代码自校验。在 x86 模拟器（ARM 转译层）下，
运行时生成的 ARM 机器码执行必然异常 → 恒返回 1 → 上层 `System.exit(0)`。

**这一步的价值**：你知道了「换模拟器没用」，不用再试蓝叠、夜神、雷电。
因为问题是架构，不是配置。

---

## 四、抓包：拿到真实的请求

两条路，优先第一条：

**A. 协议级（推荐）**

如果能找到开源的协议实现（比如有人已经还原过），直接用，省几周。
审一遍代码确认协议细节，然后自己实现。

**B. 抓包还原**

```bash
frida -U -f com.example.app -l frida_okhttp.js --no-pause
```

如果 HTTPS 抓不到内容，先绕证书固定：

```bash
frida -U -f com.example.app -l frida_ssl.js --no-pause
```

抓包时重点看：
- 请求体里哪些字段是「客户端算好传上去的」（这些是伪造时要一起造的）
- 响应里有没有 `sign` / `timestamp` / `nonce`（说明有签名，要还原算法）
- 拒绝时返回什么（`remark` 是你的 oracle）

---

## 五、探测：用拒绝原因反推规则

服务端的错误信息是一座金矿。固定其它字段，只改一个字段，看什么时候被拒：

```bash
python -m tools.probe.fuzz_fields probe.json -o result.csv
python -m tools.probe.rule_miner result.csv
```

输出：

```
字段: sportRange
  接受: [2.0, 2.1, 5.0]
  拒绝: [0.5, 1.0, 1.9]
  推断: 存在下界，介于 1.9 和 2.0 之间
```

这比读代码快得多，而且 App 升级后重跑一遍就知道规则变没变。

---

## 六、什么时候该放弃

不是所有目标都值得投入。出现下面任一情况，考虑收手：

- 校验依赖真实硬件（摄像头人脸活体、蓝牙信标、NFC）
- 服务端有人工审核（轨迹 + 人脸 + 时间三重比对）
- 每次破解都要重新对抗（周更风控）
- 收益远小于成本

**判断标准**：如果你的方案需要「每天都维护」，那它不是一个好方案。

---

## 七、工具一览

| 工具 | 用途 |
|---|---|
| `apk_scan` | 识别加固、检测库、SDK |
| `string_hunt` | 字节级定位字符串来源 |
| `elf_sym` | ELF 符号、JNI 入口、反汇编 |
| `frida_okhttp.js` | 打印 OkHttp 请求/响应 |
| `frida_ssl.js` | 证书固定绕过 |
| `fuzz_fields` | 字段边界探测 |
| `rule_miner` | 从探测结果归纳规则 |

---

## 八、一条经验

**先花 10% 的时间搞清楚「该不该做这件事」，再花 90% 的时间做。**

大部分逆向失败不是技术不够，是方向错了：
在本地改数据（数据在云端）、跟反调试硬刚（数据校验在服务端）、
在 x86 模拟器上修 ARM 原生问题（架构不匹配）。
