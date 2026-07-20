# -*- coding: utf-8 -*-
import re
import logging
import ipaddress
from typing import Tuple, Optional, Dict, Set, List

# 配置基础日志输出
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ---------------- 阶段 1: 核心数据矩阵与配置 ----------------

STRICT_DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9\-]{1,59})$'
)

PUBLIC_SUFFIX_BLACKLIST = {
    'com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'arpa', 'biz', 'info', 'name', 'pro',
    'app', 'dev', 'shop', 'club', 'top', 'xyz', 'vip', 'fun', 'site', 'online', 'tech', 'store',
    'work', 'live', 'link', 'icu', 'ltd', 'art', 'blog', 'news', 'wiki', 'chat', 'space', 'me',
    'io', 'co', 'ai', 'so', 'to', 'do', 'in', 'cc', 'tv', 'la', 'fm', 'am', 'im', 'gg',
    'run', 'pub', 'network', 'studio', 'design', 'life', 'today', 'world', 'zone', 'host',
    'cn', 'hk', 'tw', 'mo', 'jp', 'kr', 'sg', 'my', 'th', 'vn', 'ph', 'id', 'pk', 'kh', 'mm', 
    'us', 'uk', 'ca', 'au', 'de', 'fr', 'ru', 'it', 'es', 'nl', 'se', 'no', 'fi', 'dk', 'ch', 
    'at', 'be', 'ie', 'nz', 'br', 'za', 'mx', 'ar', 'cl', 'tr', 'il', 'ae', 'sa', 'ua', 'pl',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'mil.cn', 'ac.cn', 'ah.cn', 'bj.cn', 'cq.cn',
    'fj.cn', 'gd.cn', 'gs.cn', 'gz.cn', 'ha.cn', 'hb.cn', 'he.cn', 'hi.cn', 'hl.cn',
    'hn.cn', 'jl.cn', 'js.cn', 'jx.cn', 'ln.cn', 'nm.cn', 'nx.cn', 'qh.cn', 'sc.cn', 'sd.cn',
    'sh.cn', 'sn.cn', 'sx.cn', 'tj.cn', 'xj.cn', 'xz.cn', 'yn.cn', 'zj.cn',
    'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk', 'hk.org', 'hk.com',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'club.tw', 'ebiz.tw', 'game.tw',
    'com.mo', 'net.mo', 'org.mo', 'gov.mo', 'edu.mo',
    'co.uk', 'me.uk', 'org.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'sch.uk', 'net.uk',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'ed.jp', 'ad.jp', 'lg.jp',
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'mil.kr', 'ac.kr',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'co.id', 'web.id', 'or.id', 'go.id', 'ac.id',
    'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
    'com.au', 'net.au', 'org.au', 'asn.au', 'id.au', 'gov.au', 'edu.au',
    'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz', 'geek.nz', 'school.nz',
    'com.br', 'net.br', 'org.br', 'gov.br', 'co.za', 'web.za', 'org.za', 'gov.za'
}

_GROUPS = {
    'remove':    {'REMOVE'},
    'process':   {'PROCESS-NAME', 'PROCESS_NAME', 'PROCESS'},
    'port':      {'DST-PORT', 'DEST-PORT', 'PORT'},
    'full':      {'DOMAIN', 'HOST', 'FULL'},
    'suffix':    {'DOMAIN-SUFFIX', 'HOST-SUFFIX', 'DOMAIN_SUFFIX', 'SUFFIX'},
    'keyword':   {'DOMAIN-KEYWORD', 'HOST-KEYWORD', 'DOMAIN_KEYWORD', 'KEYWORD'},
    'ip':        {'IP-CIDR', 'IP'},
    'ip6':       {'IP-CIDR6', 'IP6-CIDR', 'IP6'}, 
    'asn':       {'IP-ASN', 'IP_ASN', 'ASN'},
    'useragent': {'USER-AGENT', 'USERAGENT'},
    'wildcard':  {'DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD'},
    'regex':     {'DOMAIN-REGEX', 'DOMAIN_REGEX', 'REGEX'}
}

SOURCE_KEYS = list(_GROUPS.keys())
RULE_MAP = {rule_name: target_cat for target_cat, rule_sets in _GROUPS.items() for rule_name in rule_sets}

# ---------------- 阶段 2: 内部私有高精度卡尺工具集 ----------------

def _is_exact_ip(text: str) -> Tuple[Optional[str], str]:
    """严格校验IP格式并返回其类型。"""
    if not text:
        return None, ""
    cleaned = text.strip().strip('[]')
    parts = cleaned.split('/')
    ip_body = parts[0]
    
    mask_suffix = ""
    mask_val = None
    if len(parts) > 1:
        mask_str = parts[1]
        if not mask_str.isdigit():
            return None, text
        mask_val = int(mask_str)
        mask_suffix = f"/{mask_val}"

    try:
        ip_obj = ipaddress.ip_address(ip_body)
        if ip_obj.version == 4:
            if mask_val is not None and not (0 <= mask_val <= 32):
                return None, text
            return 'ip', f"{ip_body}{mask_suffix}"
        elif ip_obj.version == 6:
            if mask_val is not None and not (0 <= mask_val <= 128):
                return None, text
            return 'ip6', f"{ip_body.lower()}{mask_suffix}"
    except ValueError:
        pass
    return None, text


def _is_exact_domain(text: str) -> Optional[str]:
    """去除冗余查找，依靠正则秒杀非法字符"""
    if not text or len(text) > 253:
        return None
        
    domain = text.strip().rstrip('.').lstrip('+*.')
    if not domain or len(domain) > 253:
        return None
        
    if ':' in domain:
        parts = domain.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            domain = parts[0]
            
    if not domain.isascii():
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return None
            
    domain = domain.lower()
    
    if STRICT_DOMAIN_REGEX.match(domain):
        return domain
        
    return None


def _clean_policy_suffix(line: str) -> str:
    """快速切除策略后缀并清洗空格。"""
    first_comma_idx = line.find(',')
    if first_comma_idx != -1:
        head = line[:first_comma_idx].strip().upper()
        if head in RULE_MAP:
            return line
        return line.split(',', 1)[0].strip()
    return line


# ---------------- ⚡ 高性能轻量字典树 ----------------

class DomainTrie:
    """用于百万级域名层级去重的后缀字典树。"""
    def __init__(self):
        self.root = {}

    def insert_suffix(self, domain: str):
        parts = domain.split('.')
        current = self.root
        for part in reversed(parts):
            if '__end__' in current:
                return
            current = current.setdefault(part, {})
        current['__end__'] = True

    def is_covered(self, domain: str) -> bool:
        parts = domain.split('.')
        current = self.root
        for part in reversed(parts):
            if '__end__' in current:
                return True
            if part not in current:
                return False
            current = current[part]
        return '__end__' in current


# ---------------- 阶段 3: 主流水线总入口 ----------------

def execute_rules_pipeline(local_raw_lines: List[str], remote_raw_lines: List[str]) -> Dict[str, Set[str]]:
    """主执行流水线。"""
    logging.info(f"开始处理规则，本地: {len(local_raw_lines)} 行，远程: {len(remote_raw_lines)} 行")
    
    local_rules = process_raw_lines_batch(local_raw_lines, SOURCE_KEYS)
    remote_rules = process_raw_lines_batch(remote_raw_lines, SOURCE_KEYS)
    
    merged_rules = merge_and_sovereignty_filter(local_rules, remote_rules, SOURCE_KEYS)
    optimize_domains(merged_rules)
    
    logging.info("[成功] 规则流水线处理完成。")
    return merged_rules


# ---------------- 阶段 4: 核心解析与格式收拢断言 ----------------

def filter_raw_line(line: str) -> Optional[str]:
    """清洗行开头的注释与多重引号（极速 O(1) 处理）。"""
    line = line.split('#')[0].split('//')[0].split(';')[0].strip()
    if not line or line.lower() == 'payload:':
        return None
    if line.startswith('- '):
        line = line[2:].strip()
        
    # 一次性剥离所有边缘空白和单双引号
    line = line.strip().strip("'\"").strip()
    return _clean_policy_suffix(line) if line else None


def _format_ip_cidr(checked_ip: str, ip_type: str) -> str:
    """自动补全 IP 的掩码位数。"""
    if '/' in checked_ip:
        return checked_ip
    return f"{checked_ip}/{'128' if ip_type == 'ip6' else '32'}"


def parse_line(line: str) -> Tuple[Optional[str], str]:
    """根据规则前缀自动分发解析。"""
    clean_line = filter_raw_line(line)
    if not clean_line:
        return None, ""

    if clean_line.startswith('|'):
        return parse_adguard_rule(clean_line)
        
    if ',' not in clean_line:
        return parse_pure_text_rule(clean_line)
        
    head, _, _ = clean_line.partition(',')
    head = head.strip().upper()

    if head in RULE_MAP:
        return parse_standard_rule(clean_line)
        
    return parse_pure_text_rule(clean_line)


def parse_standard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析标准前缀规则并严格校验域名/IP。"""
    parts = [x.strip() for x in line.split(',')]
    if len(parts) < 2:
        return None, ""

    tag = parts[0].upper()
    if tag not in RULE_MAP:
        return None, ""
    internal_type = RULE_MAP[tag]
    
    # 1. 提取并清洗 Payload
    raw_payload = parts[1] if internal_type not in ['regex', 'wildcard', 'useragent'] else ','.join(parts[1:])
    payload = raw_payload.strip().strip("'\"").strip()
    if not payload:
        return None, ""

    # 2. 域名/后缀类型：安全校验 + RFC 严格校验
    if internal_type in ['suffix', 'full']:
        ip_type, _ = _is_exact_ip(payload)
        if ip_type is not None:
            return None, ""
        exact_domain = _is_exact_domain(payload)
        if not exact_domain:
            return None, ""
        return internal_type, exact_domain

    if internal_type in ['keyword', 'process']:
        ip_type, _ = _is_exact_ip(payload)
        if ip_type is not None:
            return None, ""
        return internal_type, payload

    # 3. IP 类型校验与自动修正
    if internal_type in ['ip', 'ip6']:
        ip_type, checked_ip = _is_exact_ip(payload)
        if ip_type is None:
            return None, "" 
        if internal_type == 'ip6' and ip_type == 'ip':
            return None, "" 
        if internal_type == 'ip' and ip_type == 'ip6':
            internal_type = 'ip6'
            
        return internal_type, _format_ip_cidr(checked_ip, internal_type)
        
    # 4. PORT 端口格式化
    if internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        parts = [p.strip() for p in payload.split('-') if p.strip()]
        payload = '-'.join(parts) if parts else None
        return (internal_type, payload) if payload else (None, "")

    # 5. ASN 校验
    if internal_type == 'asn':
        if not re.match(r'^(?:[a-zA-Z]{2})?\d{1,10}$', payload):
            return None, ""
        return internal_type, payload
        
    # 6. 其他类型（useragent, regex, wildcard）
    return internal_type, payload


def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
    """无前缀纯文本分层路由算法"""
    if '*' in line and not (line.startswith('*.') or line.startswith('+.')):
        return None, ""    
    is_explicit_suffix = line.startswith('+.') or line.startswith('*.') or line.startswith('.')
    clean_val = line.lstrip('+*.')

    # 1. 优先尝试 IP 匹配
    ip_type, checked_ip = _is_exact_ip(clean_val)
    if ip_type is not None:
        if is_explicit_suffix:
            return None, "" 
        return ip_type, _format_ip_cidr(checked_ip, ip_type)

    # 2. 域名断言逻辑
    exact_domain = _is_exact_domain(clean_val)
    if not exact_domain:
        return None, "" 

    if is_explicit_suffix:
        return 'suffix', exact_domain

    if exact_domain in PUBLIC_SUFFIX_BLACKLIST:
        return None, "" 

    parts = exact_domain.split('.')
    N = len(parts)

    if N == 2:
        return 'suffix', exact_domain
    elif N == 3:
        if f"{parts[1]}.{parts[2]}" in PUBLIC_SUFFIX_BLACKLIST:
            return 'suffix', exact_domain
        return 'full', exact_domain
    else:
        return 'full', exact_domain


def parse_adguard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析 AdGuard / uBlock 格式规则"""
    core_content = line.split('$')[0].split('^')[0].strip()
    for prefix, internal_type in [('||', 'suffix'), ('|', 'full')]:
        if core_content.startswith(prefix):
            raw_payload = core_content[len(prefix):].strip()
            break
    else:
        return None, "" 

    exact_domain = _is_exact_domain(raw_payload)
    if not exact_domain:
        return None, ""

    return internal_type, exact_domain


# ---------------- 阶段 5: 优化合并与极致树状剪枝 ----------------

def process_raw_lines_batch(lines: List[str], rule_keys: List[str]) -> Dict[str, Set[str]]:
    """批量分发解析。"""
    parsed_rules = {k: set() for k in rule_keys}
    for line in lines:
        r_type, payload = parse_line(line)  
        if payload and r_type in parsed_rules:
            parsed_rules[r_type].add(payload)
    return parsed_rules


def merge_and_sovereignty_filter(
    local_rules: Dict[str, Set[str]], 
    remote_rules: Dict[str, Set[str]], 
    rule_keys: List[str]
) -> Dict[str, Set[str]]:
    """纯函数合并：本地REMOVE全局剔除，同类规则本地优先，域名去重交由Trie树。"""
    merged = {}
    local_remove = local_rules.get('remove', set())
    remote_remove = remote_rules.get('remove', set())
    
    # 汇总所有黑名单，用于全局剔除
    all_removes = local_remove | remote_remove

    for r_type in rule_keys:
        if r_type == 'remove':
            merged['remove'] = all_removes
            continue

        local_set = local_rules.get(r_type, set())
        remote_set = remote_rules.get(r_type, set())
        
        # 建立副本，不修改传入的字典对象（完全解耦）
        final_set = (local_set | remote_set) - all_removes
        merged[r_type] = final_set
        
    return merged


def optimize_domains(rules: Dict[str, Set[str]]) -> None:
    """利用 Trie 树对域名规则进行降维打击式剪枝去重"""
    suffixes = rules.get('suffix', set())
    fulls = rules.get('full', set())
    
    if not suffixes and not fulls:
        return
        
    trie = DomainTrie()
    
    # 1. 处理 SUFFIX 内部去重（短域名优先构筑 Trie 树）
    sorted_suffixes = sorted(list(suffixes), key=len)
    optimized_suffixes = set()
    
    for suf in sorted_suffixes:
        if trie.is_covered(suf):
            continue
        trie.insert_suffix(suf)
        optimized_suffixes.add(suf)

    # 2. 处理 FULL 域名去重（如果已被 SUFFIX 涵盖，直接剔除）
    optimized_fulls = set()
    for f_dom in fulls:
        if trie.is_covered(f_dom):
            continue
        optimized_fulls.add(f_dom)

    # 写回字典
    if 'suffix' in rules:
        rules['suffix'] = optimized_suffixes
    if 'full' in rules:
        rules['full'] = optimized_fulls
        
    logging.info(f"域名规则合并完成。SUFFIX: {len(optimized_suffixes)}，FULL: {len(optimized_fulls)}")
