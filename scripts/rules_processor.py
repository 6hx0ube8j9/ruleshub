# -*- coding: utf-8 -*-
import re
import logging
import ipaddress
from typing import Tuple, Optional, Dict, Set, List

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ---------------- 1. 预编译正则与基础配置 ----------------

_ALLOW_IP_CHARS_RE = re.compile(r'^[0-9a-fA-F.:]+$')
_IPV4_EXACT_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
)

# 基础结构正则：放行字母、数字、单/连续短横线及点，拒收 * + 或其他非法符号
RELAXED_DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
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

# ---------------- 2. Trie 树剪枝引擎 ----------------

class DomainTrie:
    """用于域名层级去重的后缀字典树。"""

    __slots__ = ('root',)

    def __init__(self):
        self.root = {}

    def insert_if_not_covered(self, domain: str) -> bool:
        """尝试插入后缀，若已被父域名覆盖返回 False，否则插入并返回 True。"""
        curr = self.root
        for part in reversed(domain.split('.')):
            if 0 in curr:
                return False
            curr = curr.setdefault(part, {})

        if 0 in curr:
            return False

        curr[0] = True
        return True

    def is_covered(self, domain: str) -> bool:
        """判断 FULL 域名是否被 Trie 中的 SUFFIX 覆盖。"""
        curr = self.root
        for part in reversed(domain.split('.')):
            if 0 in curr:
                return True
            if part not in curr:
                return False
            curr = curr[part]
        return 0 in curr

# ---------------- 3. 私有校验卡尺（纯函数，零侧效应） ----------------

def filter_raw_line(line: str) -> Optional[str]:
    """第一道关卡：剥离注释、边缘空白/引号及策略后缀。"""
    line = line.split('#')[0].split('//')[0].split(';')[0].strip()
    if not line or line.lower() == 'payload:':
        return None
    if line.startswith('- '):
        line = line[2:].strip()
        
    line = line.strip().strip("'\"").strip()
    if not line:
        return None

    if ',' in line:
        head, _, tail = line.partition(',')
        head_clean = head.strip()
        head_upper = head_clean.upper()

        if head_upper in RULE_MAP:
            internal_type = RULE_MAP[head_upper]
            tail_clean = tail.strip()
            if internal_type in ('regex', 'wildcard', 'useragent'):
                parts = [p.strip() for p in tail_clean.split(',')]
                payload = ','.join(parts[:-1]) if len(parts) > 1 else parts[0]
            else:
                payload = tail_clean.split(',', 1)[0].strip()
            return f"{head_upper},{payload}" if payload else None
        else:
            return head_clean

    return line


def _is_exact_ip(text: str) -> Tuple[Optional[str], str]:
    """纯粹的 IP 校验卡尺：支持 [IPv6]:port 剥离、CIDR 自动补全及 RFC 5952 规范化。"""
    if not text:
        return None, ""
    
    cleaned = text.strip()

    # 1. 剥离 [IPv6]:port 组合格式并完整还原 CIDR 掩码
    if cleaned.startswith('['):
        rb_idx = cleaned.find(']')
        if rb_idx != -1:
            ip_inside = cleaned[1:rb_idx]
            remainder = cleaned[rb_idx + 1:]
            slash_idx = remainder.find('/')
            cleaned = ip_inside + (remainder[slash_idx:] if slash_idx != -1 else "")

    parts = cleaned.split('/')
    if len(parts) > 2:
        return None, text

    ip_body = parts[0]
    if not _ALLOW_IP_CHARS_RE.match(ip_body):
        return None, text

    mask_suffix = ""
    mask_val = None
    if len(parts) == 2:
        mask_str = parts[1]
        if not mask_str.isdigit():
            return None, text
        mask_val = int(mask_str)
        mask_suffix = f"/{mask_val}"

    # IPv4 快筛与断言
    if ':' not in ip_body:
        if _IPV4_EXACT_RE.match(ip_body):
            if mask_val is not None and not (0 <= mask_val <= 32):
                return None, text
            return 'ip', f"{ip_body}{mask_suffix if mask_suffix else '/32'}"
        return None, text

    # IPv6 断言与 RFC 5952 压缩规范化
    try:
        ip_obj = ipaddress.ip_address(ip_body)
        if ip_obj.version == 6:
            if mask_val is not None and not (0 <= mask_val <= 128):
                return None, text
            return 'ip6', f"{ip_obj.compressed}{mask_suffix if mask_suffix else '/128'}"
    except ValueError:
        pass

    return None, text


def _is_exact_domain(text: str) -> Optional[str]:
    """纯粹的 FQDN 校验卡尺：绝不隐式截断任何前缀，依靠 IDNA 与正则强行断言。"""
    if not text or len(text) > 253:
        return None

    domain = text.strip().strip('[]').rstrip('.')
    if not domain:
        return None

    # 包含端口号阻断 (非域名语法)
    if ':' in domain:
        parts = domain.split(':')
        if len(parts) == 2 and parts[1].isdigit():
            domain = parts[0]
        else:
            return None

    # 纯数字 IP 段直接阻断
    sub_parts = domain.split('.')
    if all(p.isdigit() for p in sub_parts):
        return None

    # IDNA 自动转码校验 (处理中文域名，自动做小写转换)
    if not domain.isascii():
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return None

    domain = domain.lower()

    # 标准 RFC FQDN 正则断言：任何含 * 或 + 等非法字符的输入在此被直接杀掉
    if len(domain) > 253 or not RELAXED_DOMAIN_REGEX.match(domain):
        return None

    return domain

# ---------------- 4. 规则解析层（负责语义识别与显示前缀剥离） ----------------

def parse_line(line: str) -> Tuple[Optional[str], str]:
    """规则入口分发。"""
    clean_line = filter_raw_line(line)
    if not clean_line:
        return None, ""

    if clean_line.startswith('|'):
        return parse_adguard_rule(clean_line)

    if ',' in clean_line:
        return parse_standard_rule(clean_line)

    return parse_pure_text_rule(clean_line)


def parse_standard_rule(clean_line: str) -> Tuple[Optional[str], str]:
    """标准规则解析：FULL 规则拒绝篡改；SUFFIX 规则按语义剥离前缀。"""
    tag, _, payload = clean_line.partition(',')
    tag = tag.upper()
    payload = payload.strip()

    if tag not in RULE_MAP or not payload:
        return None, ""

    internal_type = RULE_MAP[tag]

    # 1. FULL 类型：绝对原封不动校验，含 * 的非法输入会被 _is_exact_domain 拦截返回 None
    if internal_type == 'full':
        exact_domain = _is_exact_domain(payload)
        return ('full', exact_domain) if exact_domain else (None, "")

    # 2. SUFFIX 类型：显式剥离通配前缀后送检
    if internal_type == 'suffix':
        for prefix in ('+*.', '+.', '*.', '.'):
            if payload.startswith(prefix):
                payload = payload[len(prefix):]
                break
        exact_domain = _is_exact_domain(payload)
        return ('suffix', exact_domain) if exact_domain else (None, "")

    if internal_type in ('keyword', 'process'):
        if _IPV4_EXACT_RE.match(payload) or (':' in payload and not payload.isalnum()):
            return None, ""
        return internal_type, payload

    if internal_type in ('ip', 'ip6'):
        ip_type, checked_ip = _is_exact_ip(payload)
        if ip_type is None:
            return None, ""
        if internal_type == 'ip6' and ip_type == 'ip':
            return None, ""
        if internal_type == 'ip' and ip_type == 'ip6':
            internal_type = 'ip6'
        return internal_type, checked_ip

    if internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        p_parts = [p.strip() for p in payload.split('-') if p.strip()]
        payload = '-'.join(p_parts) if p_parts else None
        return (internal_type, payload) if payload else (None, "")

    if internal_type == 'asn':
        if not re.match(r'^(?:[a-zA-Z]{2})?\d{1,10}$', payload):
            return None, ""
        return internal_type, payload.upper()

    return internal_type, payload


def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
    """纯文本分流：识别前缀，卡尺校验，动态 TLD 划分 suffix 与 full。"""
    if not line:
        return None, ""

    is_explicit_suffix = False
    clean_val = line

    # 显式前缀剥离
    if line[0] in ('+', '*', '.'):
        for prefix in ('+*.', '+.', '*.', '.'):
            if line.startswith(prefix):
                is_explicit_suffix = True
                clean_val = line[len(prefix):]
                break

    if '*' in clean_val:
        return None, ""

    # 短路 IP 校验：仅在首字符或特征符符合 IP 时触发
    first_char = clean_val[0]
    if first_char.isdigit() or first_char == '[' or ':' in clean_val or '/' in clean_val:
        ip_type, checked_ip = _is_exact_ip(clean_val)
        if ip_type is not None:
            if is_explicit_suffix: # 带有 +. 等前缀的 IP 属于语法错误，拒绝
                return None, ""
            return ip_type, checked_ip

    # FQDN 校验卡尺
    exact_domain = _is_exact_domain(clean_val)
    if not exact_domain:
        return None, ""

    if is_explicit_suffix:
        return 'suffix', exact_domain

    if exact_domain in PUBLIC_SUFFIX_BLACKLIST:
        return None, ""

    # 动态 TLD 深度计算分流 (suffix / full)
    parts = exact_domain.split('.')
    num_parts = len(parts)
    if num_parts < 2:
        return None, ""

    public_suffix_len = 1
    max_check_depth = min(num_parts - 1, 3)

    for depth in range(max_check_depth, 1, -1):
        if '.'.join(parts[-depth:]) in PUBLIC_SUFFIX_BLACKLIST:
            public_suffix_len = depth
            break

    root_domain_parts = public_suffix_len + 1

    if num_parts == root_domain_parts:
        return 'suffix', exact_domain
    elif num_parts > root_domain_parts:
        return 'full', exact_domain

    return None, ""


def parse_adguard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析 AdGuard 格式规则。"""
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

# ---------------- 5. 流水线执行 ----------------

def process_raw_lines_batch(lines: List[str], rule_keys: List[str]) -> Dict[str, Set[str]]:
    """批量解析。"""
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
    """合并规则并全局剔除 REMOVE。"""
    merged = {}
    all_removes = local_rules.get('remove', set()) | remote_rules.get('remove', set())

    for r_type in rule_keys:
        if r_type == 'remove':
            merged['remove'] = all_removes
            continue

        local_set = local_rules.get(r_type, set())
        remote_set = remote_rules.get(r_type, set())
        merged[r_type] = (local_set | remote_set) - all_removes

    return merged


def optimize_domains(rules: Dict[str, Set[str]]) -> None:
    """Trie 树对域名的父子覆盖剔除。"""
    suffixes = rules.get('suffix', set())
    fulls = rules.get('full', set())

    if not suffixes and not fulls:
        return

    trie = DomainTrie()
    sorted_suffixes = sorted(suffixes, key=lambda s: (s.count('.'), len(s)))

    insert_op = trie.insert_if_not_covered
    optimized_suffixes = {suf for suf in sorted_suffixes if insert_op(suf)}

    is_cov_op = trie.is_covered
    optimized_fulls = {f_dom for f_dom in fulls if not is_cov_op(f_dom)}

    if 'suffix' in rules:
        rules['suffix'] = optimized_suffixes
    if 'full' in rules:
        rules['full'] = optimized_fulls

    logging.info(f"域名规则剪枝完成。SUFFIX: {len(optimized_suffixes)}，FULL: {len(optimized_fulls)}")


def execute_rules_pipeline(local_raw_lines: List[str], remote_raw_lines: List[str]) -> Dict[str, Set[str]]:
    """主流水线。"""
    logging.info(f"开始处理规则，本地: {len(local_raw_lines)} 行，远程: {len(remote_raw_lines)} 行")
    
    local_rules = process_raw_lines_batch(local_raw_lines, SOURCE_KEYS)
    remote_rules = process_raw_lines_batch(remote_raw_lines, SOURCE_KEYS)
    
    merged_rules = merge_and_sovereignty_filter(local_rules, remote_rules, SOURCE_KEYS)
    optimize_domains(merged_rules)
    
    logging.info("[成功] 规则流水线处理完成。")
    return merged_rules
