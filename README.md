# 🏴‍☠️ Flag Hunter -- FLAG捡漏神器
由 Hx0 战队 开发的，本人稍微完善了一下，纯ai，勿喷

添加了几个参数，使搜索flag的范围更广

🧩 配置文件说明 (config.yml)
flag_simple_rules:
  # 示例 1：搜索 "flag"，启用所有编码模式（默认推荐）
  - prefix: "flag"
    variants:
      plaintext: true
      base64: true
      hex_curly: true
      hex_plain: true

flag_regular_rules:
  # 示例 2：匹配任意以 ctf 结尾或包含 ctf 的格式，如 ANYctf{...}，需要配合参数`r`使用
  - regex: "^.*ctf.*$"
    variants:
      plaintext: true  # 扫描明文流中的正则命中
      base64: true     # 扫描被混淆为 Base64 的正则命中
      hex_curly: true  # 扫描形如 616e796374667b... 的 Hex
      hex_plain: true  # 扫描无括号的纯 Hex 命中

参数：
usage: main.py [-h] [-d DIR] [-f FILE] [-u URL] [-e] [-r]

Advanced CTF Flag Hunter Engine (Dual-Pipeline)

optional arguments:
  -h, --help            show this help message and exit
  -d DIR, --dir DIR     指定扫描目标目录
  -f FILE, --file FILE  扫描单个文件
  -u URL, --url URL     扫描目标 URL (例如提取 HTML 注释/前端源码中的 Flag)
  -e, --exif            尝试提取目标文件的 EXIF/元数据
  -r, --regex           启用 Stage 2 深度正则匹配引擎 (用于提取高混淆 Flag，性能损耗较大)

🖥️ 使用方法
1. 安装依赖
pip3 install pyyaml watchdog urllib pyexiftool

2. 填写exiftool路径
在 `main.py` 里面

3. 使用
python3 FlagHunter -h




