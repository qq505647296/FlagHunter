#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import base64
import binascii
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger("RegularEngine")

@dataclass
class RegularScanResult:
    regex_pattern: str
    variant: str
    offset: int
    raw_payload: bytes  # 提取出的 Base64/Hex 原始块
    matched_flag: bytes # 经过正则匹配出的最终 Flag 明文

def build_regular_regex(rules: List[Dict[str, Any]]) -> List[Tuple[re.Pattern, Dict[str, bool]]]:
    """
    解析 YAML 的 flag_regular_rules 节点
    返回格式: [(编译好的用户正则, 启用的变体字典), ...]
    """
    compiled_rules = []
    for rule in rules:
        regex_str = rule.get('regex', '')
        variants = rule.get('variants', {})
        if not regex_str:
            continue
        try:
            # 编译用户定义的复杂正则，通常使用多行和忽略大小写模式
            pattern = re.compile(regex_str.encode('utf-8'), re.IGNORECASE | re.MULTILINE)
            compiled_rules.append((pattern, variants))
        except Exception as e:
            logger.error(f"无法编译用户正则表达式 '{regex_str}': {e}")
            
    return compiled_rules

def _extract_and_match(buffer: bytes, compiled_rules: List[Tuple[re.Pattern, Dict[str, bool]]], variant_type: str) -> List[RegularScanResult]:
    """内部辅助函数：执行正则匹配校验"""
    results = []
    for pattern, variants in compiled_rules:
        if not variants.get(variant_type):
            continue
            
        for match in pattern.finditer(buffer):
            results.append(RegularScanResult(
                regex_pattern=pattern.pattern.decode('utf-8', errors='ignore'),
                variant=variant_type,
                offset=match.start(),
                raw_payload=b"", # 如果是明文流匹配，原始 payload 即为明文本身
                matched_flag=match.group(0)
            ))
    return results

def scan_regular(buffer: bytes, compiled_rules: List[Tuple[re.Pattern, Dict[str, bool]]]) -> List[RegularScanResult]:
    """
    执行 Stage 2 深度动态正则扫描
    """
    results = []

    # 1. Plaintext 扫描：直接在原始 buffer 上应用正则
    results.extend(_extract_and_match(buffer, compiled_rules, "plaintext"))

    # 2. 暴力提取 Base64 数据块并解码匹配
    # 提取长度大于 20 的合法 Base64 字符块
    b64_extractor = re.compile(b'[A-Za-z0-9+/]{20,}={0,2}')
    for match in b64_extractor.finditer(buffer):
        raw_chunk = match.group(0)
        pad = len(raw_chunk) % 4
        if pad: raw_chunk += b'=' * (4 - pad)
        
        try:
            decoded_chunk = base64.b64decode(raw_chunk, validate=True)
            # 在解码后的块中寻找正则匹配
            for res in _extract_and_match(decoded_chunk, compiled_rules, "base64"):
                res.raw_payload = raw_chunk
                res.offset = match.start() # 修正偏移量为原始 buffer 中的位置
                results.append(res)
        except binascii.Error:
            pass

    # 3. 暴力提取 Hex 数据块并解码匹配
    # 提取长度大于 30 的连续 Hex 字符块
    hex_extractor = re.compile(b'[0-9a-fA-F]{30,}')
    for match in hex_extractor.finditer(buffer):
        raw_chunk = match.group(0)
        if len(raw_chunk) % 2 != 0:
            raw_chunk = raw_chunk[:-1]
            
        try:
            decoded_chunk = binascii.unhexlify(raw_chunk)
            # 在解码后的块中寻找正则匹配 (由于 Hex 可能带/不带大括号，统一在此处理)
            for res in _extract_and_match(decoded_chunk, compiled_rules, "hex"):
                res.variant = "hex_extracted"
                res.raw_payload = raw_chunk
                res.offset = match.start()
                results.append(res)
        except binascii.Error:
            pass

    return results