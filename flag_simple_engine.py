#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import base64
import binascii
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger("SimpleEngine")

@dataclass
class SimpleScanResult:
    rule_prefix: str
    variant: str
    offset: int
    raw_match: bytes
    decoded: bytes = b""

def _generate_b64_offsets(prefix: str) -> List[bytes]:
    """计算 Base64 在不同内存对齐状态下的 3 种特征码"""
    base_str = (prefix + "{").encode('utf-8')
    patterns = []
    for i in range(3):
        padded = (b"X" * i) + base_str
        encoded = base64.b64encode(padded)
        
        # 【终极修复】：使用 b"=" 彻底杜绝 b='=' 的视觉歧义和误敲击
        if i == 0: 
            patterns.append(encoded.rstrip(b"="))
        elif i == 1: 
            patterns.append(encoded[2:].rstrip(b"="))
        else: 
            patterns.append(encoded[3:].rstrip(b"="))
            
    return list(set(patterns))

def build_simple_regex(rules: List[Dict[str, Any]]) -> List[Tuple[str, str, re.Pattern]]:
    """
    解析 YAML 的 flag_simple_rules 节点
    返回格式: [(前缀, 变体类型, 编译好的正则对象), ...]
    """
    compiled_patterns = []
    
    for rule in rules:
        prefix = rule.get('prefix', '')
        variants = rule.get('variants', {})
        if not prefix:
            continue
            
        prefix_b = prefix.encode('utf-8')
        
        # 1. Plaintext 匹配
        if variants.get('plaintext'):
            pattern = re.compile(re.escape(prefix_b) + b'\\{.*?\\}', re.IGNORECASE)
            compiled_patterns.append((prefix, "plaintext", pattern))
            
        # 2. Base64 匹配 (包含对齐修复)
        if variants.get('base64'):
            b64_cores = _generate_b64_offsets(prefix)
            b64_regex = b'(?:' + b'|'.join([re.escape(c) for c in b64_cores]) + b')[A-Za-z0-9+/]+={0,2}'
            compiled_patterns.append((prefix, "base64", re.compile(b64_regex)))
            
        # 3. Hex 匹配 (带大括号 hex_curly)
        if variants.get('hex_curly'):
            hex_prefix = binascii.hexlify(prefix_b + b'{')
            pattern = re.compile(re.escape(hex_prefix) + b'(?:[0-9a-fA-F]{2})+', re.IGNORECASE)
            compiled_patterns.append((prefix, "hex_curly", pattern))
            
        # 4. 纯 Hex 匹配 (无大括号 hex_plain，极易误报，需谨慎匹配长度)
        if variants.get('hex_plain'):
            hex_prefix_plain = binascii.hexlify(prefix_b)
            # 假设 flag 至少有 10 个字符
            pattern = re.compile(re.escape(hex_prefix_plain) + b'[0-9a-fA-F]{20,}', re.IGNORECASE)
            compiled_patterns.append((prefix, "hex_plain", pattern))

    return compiled_patterns

def scan_simple(buffer: bytes, patterns: List[Tuple[str, str, re.Pattern]]) -> List[SimpleScanResult]:
    """执行 Stage 1 静态扫描"""
    results = []
    for prefix, variant, regex in patterns:
        for match in regex.finditer(buffer):
            raw = match.group(0)
            decoded = None
            
            if variant == "base64":
                pad = len(raw) % 4
                raw_padded = raw + b'=' * (4 - pad) if pad else raw
                try: decoded = base64.b64decode(raw_padded, validate=False)
                except: pass
            elif variant in ["hex_curly", "hex_plain"]:
                raw_even = raw if len(raw) % 2 == 0 else raw[:-1]
                try: decoded = binascii.unhexlify(raw_even)
                except: pass
            
            results.append(SimpleScanResult(
                rule_prefix=prefix, variant=variant, offset=match.start(), raw_match=raw, decoded=decoded or b""
            ))
    return results
