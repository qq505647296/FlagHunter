#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flag Hunter - 核心调度引擎
架构：双管线引擎 (Stage 1: 静态极速匹配 -> Stage 2: 动态正则深度提取)
"""

import os
import sys
import mmap
import yaml
import argparse
import urllib.request
import urllib.error
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ==========================================
# 🔧 用户自定义配置区 (User Configuration)
# ==========================================
# EXIFTOOL_PATH: 请在此填写本地 exiftool.exe 的绝对路径。
# 建议使用 r"..." 格式以避免反斜杠转义问题。
# 若留空 ("")，程序将尝试从系统环境变量(PATH)中调用。
EXIFTOOL_PATH = r"E:\tools\MetaSword\Tools\Forensics\exiftool\exiftool.exe"
# ==========================================

# 引入两个独立的底层引擎及其对应的数据结构
from flag_simple_engine import build_simple_regex, scan_simple, SimpleScanResult
from flag_regular_rules import build_regular_regex, scan_regular, RegularScanResult

# 将路径硬绑定到 main.py 所在的真实目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'config.yml')
LOG_FILE = os.path.join(SCRIPT_DIR, 'found_flags.log')

class Colors:
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

IS_WIN = sys.platform.startswith('win')

print_lock = threading.Lock()
log_lock = threading.Lock()
flag_counter = 0

def banner():
    with print_lock:
        print(f"""{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
   ███████╗██╗      █████╗  ██████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
   ██╔════╝██║     ██╔══██╗██╔════╝      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   █████╗  ██║     ███████║██║  ███╗     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ██╔══╝  ██║     ██╔══██║██║   ██║     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ██║     ███████╗██║  ██║╚██████╔╝     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
╚══════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
{Colors.CYAN}{Colors.BOLD}  [*] Advanced CTF Flag Hunter Engine{Colors.ENDC}

{Colors.YELLOW}  [+] Original Coded By:{Colors.ENDC} {Colors.GREEN}Hx0战队{Colors.ENDC}
{Colors.YELLOW}  [+] Modified & Optimized By:{Colors.ENDC} {Colors.CYAN}chen7chen{Colors.ENDC}
{Colors.YELLOW}  [+] Architecture:{Colors.ENDC} {Colors.BOLD}v6.0 (Dual-Pipeline Generation){Colors.ENDC}
{Colors.GREEN}============================================================================{Colors.ENDC}
""")

def get_time() -> str:
    return datetime.now().strftime("%H:%M:%S")

def log_info(msg: str):
    with print_lock:
        print(f"{Colors.CYAN if not IS_WIN else ''}[{get_time()}] [INFO] {msg}{Colors.ENDC}")

def log_warn(msg: str):
    with print_lock:
        print(f"{Colors.YELLOW if not IS_WIN else ''}[{get_time()}] [WARN] {msg}{Colors.ENDC}")

def log_error(msg: str):
    with print_lock:
        print(f"{Colors.RED if not IS_WIN else ''}[{get_time()}] [ERROR] {msg}{Colors.ENDC}")

def load_config() -> dict:
    """加载 YAML 配置文件"""
    if not os.path.exists(CONFIG_FILE):
        log_error(f"配置文件缺失: {CONFIG_FILE}，请确保 config.yml 与 main.py 在同一目录。")
        sys.exit(1)
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log_error(f"加载 YAML 配置失败: {e}")
        sys.exit(1)

def save_log(text: str):
    try:
        with log_lock:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(text + "\n\n")
    except Exception as e:
        log_warn(f"无法写入日志: {e}")

def process_results(matches: list, source_name: str, buffer: bytes, ctx_bytes: int):
    """统一处理底层引擎返回的结果"""
    global flag_counter
    for match in matches:
        with log_lock:
            flag_counter += 1
            current_count = flag_counter

        if isinstance(match, SimpleScanResult):
            rule_name = f"Simple [{match.rule_prefix}] ({match.variant})"
            offset = match.offset
            found_bytes = match.raw_match
            decoded_bytes = match.decoded
        elif isinstance(match, RegularScanResult):
            rule_name = f"Regex [{match.regex_pattern}] ({match.variant})"
            offset = match.offset
            found_bytes = match.matched_flag
            decoded_bytes = match.raw_payload
        else:
            continue

        try:
            flag_text = found_bytes.decode('utf-8')
        except UnicodeDecodeError:
            flag_text = repr(found_bytes)

        decoded_text = None
        if decoded_bytes:
            try:
                decoded_text = decoded_bytes.decode('utf-8')
            except UnicodeDecodeError:
                decoded_text = repr(decoded_bytes)

        line_num = 1 + buffer[:offset].count(b'\n')
        ctx_start = max(0, offset - ctx_bytes)
        ctx_end = min(len(buffer), offset + len(found_bytes) + ctx_bytes)
        ctx = buffer[ctx_start:ctx_end].decode('utf-8', errors='replace')

        border = f"{Colors.GREEN}{'=' * 60}{Colors.ENDC}"
        output = [
            f"\n{border}",
            f"{Colors.BOLD}{Colors.GREEN}[ FLAG FOUND #{current_count} ]{Colors.ENDC}",
            f"{Colors.CYAN}时间:{Colors.ENDC} {get_time()}",
            f"{Colors.CYAN}来源:{Colors.ENDC} {source_name}",
            f"{Colors.CYAN}规则:{Colors.ENDC} {rule_name}",
            f"{Colors.CYAN}行号:{Colors.ENDC} {line_num}  |  {Colors.CYAN}偏移:{Colors.ENDC} {hex(offset)}",
            f"{Colors.CYAN}命中:{Colors.ENDC} {Colors.RED}{flag_text}{Colors.ENDC}"
        ]
        
        if decoded_text and decoded_bytes != found_bytes:
            output.append(f"{Colors.CYAN}底层块:{Colors.ENDC} {Colors.YELLOW}{decoded_text}{Colors.ENDC}")
            
        output.extend([f"{Colors.CYAN}上下文:{Colors.ENDC}", f"{Colors.YELLOW}{ctx.strip()}{Colors.ENDC}", border])
        
        with print_lock:
            print("\n".join(output))

        log_content = (
            "=" * 40 + "\n"
            f"Flag #{current_count}\nSource: {source_name}\nRule: {rule_name}\nLine: {line_num}\nOffset: {hex(offset)}\nHit: {flag_text}\n"
            + (f"Base Chunk: {decoded_text}\n" if decoded_text and decoded_bytes != found_bytes else "")
            + f"Context:\n{ctx.strip()}\n" + "=" * 40
        )
        save_log(log_content)

def scan_exif(file_path: str, compiled_rules, scan_function, ctx_bytes: int):
    """提取文件的 EXIF 元数据并送入引擎扫描"""
    try:
        import exiftool
    except ImportError:
        log_warn("未安装 PyExifTool，跳过 EXIF 扫描。(请执行 pip install pyexiftool)")
        return

    try:
        if EXIFTOOL_PATH and os.path.exists(EXIFTOOL_PATH):
            et_helper = exiftool.ExifToolHelper(executable=EXIFTOOL_PATH)
        else:
            et_helper = exiftool.ExifToolHelper()

        with et_helper as et:
            metadata = et.get_metadata(file_path)
            if not metadata: return
            
            for d in metadata:
                for tag, value in d.items():
                    if isinstance(value, str):
                        val_bytes = value.encode('utf-8', errors='ignore')
                        matches = scan_function(val_bytes, compiled_rules)
                        if matches:
                            process_results(matches, f"{os.path.basename(file_path)} [EXIF: {tag}]", val_bytes, ctx_bytes)
    except Exception as e:
        log_warn(f"解析 EXIF 失败 {os.path.basename(file_path)}: {e}")

def scan_file(file_path: str, compiled_rules, scan_function, ctx_bytes: int, do_exif: bool = False):
    """通用文件扫描接口"""
    if os.path.abspath(file_path) == os.path.abspath(LOG_FILE):
        return

    try:
        if do_exif and file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.webp', '.pdf', '.pcap', '.wav')):
            scan_exif(file_path, compiled_rules, scan_function, ctx_bytes)

        with open(file_path, 'rb') as f:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return
                
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    matches = scan_function(mm, compiled_rules)
                    process_results(matches, file_path, mm, ctx_bytes)
            except Exception:
                buffer = f.read()
                matches = scan_function(buffer, compiled_rules)
                process_results(matches, file_path, buffer, ctx_bytes)
                
    except Exception as e:
        log_warn(f"跳过文件 {file_path}: {e}")

def scan_url(url: str, compiled_rules, scan_function, ctx_bytes: int):
    """抓取 URL 内容并送入引擎扫描 (专杀 Web 源码/前端配置隐写)"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    log_info(f"正在建立网络连接抓取: {url}")
    try:
        # 伪造 User-Agent，规避 CTF 赛棍常用的简易拦截逻辑
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CTF-FlagHunter/6.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            buffer = response.read()
            
        if not buffer:
            log_warn(f"URL 返回的 Payload 为空: {url}")
            return
            
        # 直接把抓取到的二进制流丢给引擎去打
        matches = scan_function(buffer, compiled_rules)
        if not matches:
            log_info(f"在 {url} 源码中未发现 Flag。")
        else:
            process_results(matches, f"URL: {url}", buffer, ctx_bytes)
            
    except urllib.error.URLError as e:
        log_error(f"URL 请求失败 {url}: {e.reason}")
    except Exception as e:
        log_error(f"解析 URL 异常 {url}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced CTF Flag Hunter Engine (Dual-Pipeline)")
    parser.add_argument('-d', '--dir', type=str, help="指定扫描目标目录")
    parser.add_argument('-f', '--file', type=str, help="扫描单个文件")
    parser.add_argument('-u', '--url', type=str, help="扫描目标 URL (例如提取 HTML 注释/前端源码中的 Flag)")
    parser.add_argument('-e', '--exif', action='store_true', help="尝试提取目标文件的 EXIF/元数据")
    parser.add_argument('-r', '--regex', action='store_true', 
                        help="启用 Stage 2 深度正则匹配引擎 (用于提取高混淆 Flag，性能损耗较大)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if IS_WIN: 
        os.system("color")

    args = parser.parse_args()
    banner()

    config = load_config()
    ctx_bytes = config.get('context_bytes', 40)
    max_threads = config.get('max_threads', os.cpu_count() or 4)

    if args.regex:
        log_info(f"{Colors.YELLOW}警告: 已启用 Stage 2 深度正则提取引擎，这可能需要更长的扫描时间。{Colors.ENDC}")
        raw_rules = config.get('flag_regular_rules', [])
        if not raw_rules:
            log_error("在 config.yml 中未找到 'flag_regular_rules' 节点！")
            sys.exit(1)
            
        compiled_rules = build_regular_regex(raw_rules)
        active_scan_func = scan_regular
    else:
        log_info(f"{Colors.GREEN}已启用 Stage 1 极速静态匹配引擎。{Colors.ENDC}")
        raw_rules = config.get('flag_simple_rules', [])
        if not raw_rules:
            log_error("在 config.yml 中未找到 'flag_simple_rules' 节点！")
            sys.exit(1)
            
        compiled_rules = build_simple_regex(raw_rules)
        active_scan_func = scan_simple

    if not compiled_rules:
        log_error("编译规则集失败，请检查配置文件中的语法。")
        sys.exit(1)

    # ===============
    # 任务分发中心
    # ===============
    if args.url:
        scan_url(args.url, compiled_rules, active_scan_func, ctx_bytes)

    if args.file:
        if os.path.isfile(args.file): 
            scan_file(args.file, compiled_rules, active_scan_func, ctx_bytes, args.exif)
        else: 
            log_error(f"指定的目标文件不存在: {args.file}")

    if args.dir:
        if os.path.isdir(args.dir):
            log_info(f"启动多线程目录扫描，线程数: {max_threads}，目标: {args.dir}")
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for root, _, files in os.walk(args.dir):
                    for name in files:
                        file_path = os.path.join(root, name)
                        executor.submit(scan_file, file_path, compiled_rules, active_scan_func, ctx_bytes, args.exif)
            log_info("多线程扫描队列已全部执行完毕。")
        else:
            log_error(f"指定的目录无效: {args.dir}")

if __name__ == "__main__":
    main()