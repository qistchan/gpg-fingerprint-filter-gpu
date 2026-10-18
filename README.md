## gpg-fingerprint-filter-gpu

Generate an OpenPGP key whose fingerprint matches a specific pattern.

Get your lucky key! CUDA powered, so fast!

## Python runner（中文）

`vanity.py` 是一个只使用 Python 3.11 标准库的安全包装器：它把多个 vanity
规则展开成原生程序支持的 OR pattern，每次原生调用只生成一个结果，再用隔离的
`gpg` 环境验证完整 40 位指纹。它不会使用原生程序的 `-m` batch 模式。

### 依赖与构建

需要 CUDA Toolkit（含 NVRTC）、可用的 NVIDIA 驱动、`gpg`、`libgcrypt`
开发包、`make`、`pkg-config` 和支持 CUDA 的 `g++`。例如 Ubuntu 可安装
`gnupg libgcrypt20-dev pkg-config make`，CUDA Toolkit/驱动请按 NVIDIA
官方方式安装。A100（SM 8.0）可用以下构建命令：

```sh
make NVCCFLAGS='-O3 -std=c++14 --compiler-options -Wall,-Wextra -arch=sm_80'
```

本项目尚未在本机 A100 上实测；80 GB 显存不是运行所必需的。`/data` 必须是
容器或主机中可写的持久挂载点，否则请显式指定一个可写的 `--data-dir`。包装器
不会修改共享的 `/data` 权限，只会为每个任务创建权限为 0700 的独立目录。

### 运行

```sh
python3 vanity.py \
  --rule suffix:DEADBEEF \
  --data-dir /data/gpg-vanity \
  --count 1 --timeout 3600
```

至少需要一个 `--rule` 或 `--pattern`；两者都可重复传入。例如可同时使用多条
规则和多个原生 pattern：

```sh
python3 vanity.py \
  --rule suffix:DEADBEEF --rule repeat:8 \
  --pattern 'A{4}' --pattern '(XY){3}'
```

所有规则和 pattern 会合并为 OR，且不是完整正则表达式，只匹配指纹末尾：

| 规则 | 范围和含义 |
| --- | --- |
| `suffix:HEX` | 末尾 1–40 位十六进制字符，大小写不敏感 |
| `repeat:N` | 同一变量重复 N 次（2–40） |
| `pair:N` | `XY` 重复 N 次（2–20）；`X` 与 `Y` 可以取相同值 |
| `sequence:N` | 连续升序或降序十六进制（2–16），不循环 |
| `palindrome:N` | 回文（2–40） |

不同变量字母可以取相同值；例如 `XY` 不要求两个字符不同。规则展开最多
256 个 pattern，每个展开 pattern 最多 40 位，以避免原生解析器的限制。
`--threads-per-block` 必须是 32–1024 的 32 的倍数（默认 512），
`--gpg-threads` 为 1–1024（默认 CPU 数），`--time-offset` 为不超过
有符号 32 位整数、至少为线程块大小且可被线程块大小整除的正数，
`--base-time` 为不超过
无符号 32 位整数且不小于 `--time-offset`。`--count` 为 1–10000；
`--timeout` 是每次原生调用的有限正数秒数；它不限制整次任务。每次 GPG
指纹验证另有 30 秒上限。

`--gpu` 会设置 `CUDA_VISIBLE_DEVICES`。默认可执行文件是与 `vanity.py`
同目录的 `gpg-fingerprint-filter-gpu`。`--dry-run` 只验证规则和参数并打印
JSON command/config，不检查 GPU、二进制或 `gpg`，不创建目录、不联网。真实运行
时，仅在显式指定 `--gpu` 时覆盖原生子进程的 `CUDA_VISIBLE_DEVICES`；省略时
沿用继承值。运行会打印任务和日志目录；每次尝试有独立日志，`manifest.json`
原子更新且为 0600。任务目录结构如下：

```text
<data-dir>/<UTC时间>-<随机标识>/
├── manifest.json
├── gnupg/                  # 隔离的 GPG home
├── keys/
│   └── attempt-00001/
│       └── <generated-key>.gpg
└── logs/
    └── attempt-00001.log
```

生成的私钥文件不加密。请先用一次性测试密钥验证流程；若将未加密密钥用于
生产环境，必须妥善保护其文件和存储介质，绝不要上传或提交。SIGINT/SIGTERM
会停止并回收当前子进程组，最多等待 5 秒后强制终止；已找到的结果和失败日志
会保留，不会覆盖旧任务。包装器只接受 `gpg` 的隔离指纹结果，不把原生 stdout
当作成功依据。现有的 UID 导入/编辑说明仍适用。

### 飞书通知

可选地通过环境变量配置通知（不要把真实 token 或 secret 写进命令行、配置、
manifest 或日志）：

```sh
export FEISHU_WEBHOOK_URL='https://open.feishu.cn/open-apis/bot/v2/hook/REPLACE_ME'
```

`FEISHU_WEBHOOK_URL` 是可选配置；若启用，URL 必须是
`https://open.feishu.cn/open-apis/bot/v2/hook/` 下的地址。
`FEISHU_WEBHOOK_SECRET`（签名密钥）和 `FEISHU_WEBHOOK_KEYWORD`（关键词前缀）
都是可选的。通知包含开始、每个已验证匹配、完成或失败/中断事件；网络/限流
失败只告警，不会删除密钥或把成功生成改成失败。Webhook 凭据不会传给原生或
`gpg` 子进程，也不会写入 manifest、日志或通知。生成的私钥文件本身会由
`gpg` 子进程读取以便验证，但不会放入通知内容。没有设置 URL 时不发生网络请求。

### 测试

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q vanity.py vanity_rules.py tests
```

```
$ ./gpg-fingerprint-filter-gpu --help
  gpg-fingerprint-filter-gpu [OPTIONS] <pattern> <output>

  <pattern>                   Key pattern to match, for example 'X{8}|(AB){4}'
  <output>                    Save secret key to this path
  -a, --algorithm <ALGO>      PGP key algorithm [default: rsa]
  -t, --time-offset <N>       Max key timestamp offset [default: 15552000]
  -w, --thread-per-block <N>  CUDA thread number per block [default: 512]
  -j, --gpg-thread <N>        Number of threads to generate keys [default: 12]
  -b, --base-time <N>         Base key timestamp (0 means current time) [default: 0]
  -h, --help
```

### Pattern

- Only matches end part of a string.
- A hex digit means itself.
- Other Latin alphabets (`g` to `z`) are to match any hex digit.
- `{N}` to repeat previous digit or group for N times.
- `(PATTERN)` a group pattern.
- Use `|` to split multiple patterns.

Examples:

- `deadbeef` equals to regex `deadbeef$`
- `x{8}` equals to regex `([0-9a-f])\1{7}$`
- `(xy){4}` equals to regex `([0-9a-f][0-9a-f])\1{3}$`
- `xxxxa{4}` equals to regex `([0-9a-f])\1{3}aaaa$`

### Import Key

Import the generated private key:

```
$ gpg --allow-non-selfsigned-uid --import private.pgp
```

The private key file doesn't have a self-signed UID on it. GPG will display `NONAME` as the default UID.
You need to add a valid UID and remove the default one to make the key usable:

```
$ gpg --edit-key <KEY_FINGERPRINT>
gpg> adduid
Real name: Your Name Here
Email address: your_email@example.com
......
gpg> uid 1
gpg> deluid
gpg> save
```

### Merge Key

Since cv25519 cannot be used as primary key, you need to merge the generated key with an existing key:

Reference: https://security.stackexchange.com/questions/32935/migrating-gpg-master-keys-as-subkeys-to-new-master-key

TLDR:

1. Primary key should be created earlier than subkey. 
2. To persevere the subkey fingerprint, you need perserve the subkey creation time.

```
gpg -k --with-colons
gpg --with-keygrip -k
gpg --expert --faked-system-time="[sub key timestamp]\!" --ignore-time-conflict --edit-key [master key id]
addkey
13 (existing key)
```