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

_TRAILING_POLICY_RE = re.compile(r',\s*([a-zA-Z0-9_\-\.\'"\u4e00-\u9fa5\s]+)\s*$')
_INVALID_POLICY_CHARS_RE = re.compile(r'[\\*?^$\[\](){}|/<>:]')

# 基础结构正则
RELAXED_DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])?\.)*'
    r'[a-zA-Z0-9_](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])?$'
)

# 显式前缀标识符常量定义
DOMAIN_PREFIXES = ('+*.', '+.', '*.', '.')

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
    'wildcard':  {'DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD'},
    'regex':     {'DOMAIN-REGEX', 'DOMAIN_REGEX', 'REGEX'},
    'url-regex': {'URL-REGEX', 'URL_REGEX'},
    'useragent': {'USER-AGENT', 'USERAGENT'},
    'geosite':   {'GEOSITE', 'GEO-SITE'},
    'ip':        {'IP-CIDR', 'IP'},
    'ip6':       {'IP-CIDR6', 'IP6-CIDR', 'IP6'},
    'asn':       {'IP-ASN', 'IP_ASN', 'ASN'},
    'geoip':     {'GEOIP', 'GEO-IP'}
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


# ---------------- 3. 独立前缀处理与校验卡尺 ----------------

def strip_domain_prefix(text: str) -> Tuple[bool, str]:
    """独立前缀剥离管道：纯函数，剥离显式后缀前缀 (+*., +., *., .)"""
    for prefix in DOMAIN_PREFIXES:
        if text.startswith(prefix):
            return True, text[len(prefix):]
    return False, text


def filter_raw_line(line: str) -> Optional[str]:
    """第 1 层漏斗：纯物理清洗（排除正则类型）。"""
    if not line:
        return None

    line = line.strip()
    if not line or line.lower() == 'payload:':
        return None

    # 1. 优先剥离 YAML 列表项前缀 "- " 和边缘单双引号
    if line.startswith('- '):
        line = line[2:].strip()
    line = line.strip("'\"").strip()
    
    if not line:
        return None

    # 2. 嗅探规则类型 (Tag)
    tag = line.split(',', 1)[0].strip().upper()   
    immune_tags = _GROUPS['regex'] | _GROUPS['useragent'] | _GROUPS['wildcard'] | _GROUPS['url-regex']

    # 3. 精准条件清洗
    if tag not in immune_tags:
        line = line.split('#')[0].split('//')[0].split(';')[0].strip()

    if not line:
        return None

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


def _is_exact_domain(text: str, allow_single_label: bool = False) -> Optional[str]:
    """纯粹的 FQDN 校验卡尺：绝不隐式截断任何前缀，依靠 IDNA 与正则强行断言。"""
    if not text or len(text) > 253:
        return None

    domain = text.strip().strip('[]').rstrip('.')
    if not domain:
        return None

    # 包含端口号阻断
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

    # 单段域名上下文判断
    if not allow_single_label and '.' not in domain:
        return None

    # IDNA 自动转码校验
    if not domain.isascii():
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return None

    domain = domain.lower()

    # 标准 RFC 域名正则断言
    if len(domain) > 253 or not RELAXED_DOMAIN_REGEX.match(domain):
        return None

    return domain


def _is_valid_policy_name(text: str) -> bool:
    """判定是否为纯净策略名（排除正则元字符及 URL 协议）。"""
    if not text or _INVALID_POLICY_CHARS_RE.search(text):
        return False
    if text.lower().startswith(('http://', 'https://')):
        return False
    return True

# ---------------- 4. 规则解析层 ----------------

def parse_line(line: str, has_policy: bool = True) -> Tuple[Optional[str], str]:
    """规则入口分发"""
    clean_line = filter_raw_line(line)
    if not clean_line:
        return None, ""

    if clean_line.startswith('|'):
        return parse_adguard_rule(clean_line)

    if ',' in clean_line:
        return parse_standard_rule(clean_line, has_policy=has_policy)

    return parse_pure_text_rule(clean_line)


def parse_standard_rule(clean_line: str, has_policy: bool = True) -> Tuple[Optional[str], str]:
    """语义解析与策略切除。"""   
    if ',' not in clean_line:
        return None, ""

    tag, _, tail = clean_line.partition(',')
    tag = tag.strip().upper()
    tail = tail.strip()

    if tag not in RULE_MAP or not tail:
        return None, ""

    internal_type = RULE_MAP[tag]

    # 1. 特殊类型 (regex, wildcard, useragent)：精确剥离尾部策略名
    if internal_type in ('regex', 'wildcard', 'useragent', 'url-regex'):
        if has_policy and ',' in tail:
            match = _TRAILING_POLICY_RE.search(tail)
            if match:
                candidate_policy = match.group(1).strip("'\"")
                if _is_valid_policy_name(candidate_policy):
                    payload = tail[:match.start()].strip()
                    if payload:
                        return internal_type, payload
        return internal_type, tail

    # 2. 普通类型：取首个逗号前的内容作为 Payload
    payload = tail.split(',')[0].strip().strip("'\"")
    if not payload:
        return None, ""

    # 3. 校验卡尺与语义规范化
    if internal_type == 'full':
        exact_domain = _is_exact_domain(payload, allow_single_label=False)
        return ('full', exact_domain) if exact_domain else (None, "")

    if internal_type == 'suffix':
        _, payload = strip_domain_prefix(payload)
        exact_domain = _is_exact_domain(payload, allow_single_label=True)
        return ('suffix', exact_domain) if exact_domain else (None, "")

    # 4. 关键字卡尺
    if internal_type == 'keyword':
        if _IPV4_EXACT_RE.match(payload) or ':' in payload or '/' in payload:
            return None, ""
        return internal_type, payload

    # 5. 进程名卡尺
    if internal_type == 'process':
        if _IPV4_EXACT_RE.match(payload):
            return None, ""
        return internal_type, payload

    # 6. IP / IP6 卡尺
    if internal_type in ('ip', 'ip6'):
        ip_type, checked_ip = _is_exact_ip(payload)
        if ip_type is None:
            return None, ""
        if internal_type == 'ip6' and ip_type == 'ip':
            return None, ""
        if internal_type == 'ip' and ip_type == 'ip6':
            internal_type = 'ip6'
        return internal_type, checked_ip

    # 7. 端口卡尺
    if internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        p_parts = [p.strip() for p in payload.split('-') if p.strip()]
        payload = '-'.join(p_parts) if p_parts else None
        return (internal_type, payload) if payload else (None, "")

    # 8. ASN 卡尺
    if internal_type == 'asn':
        if not re.match(r'^(?:[a-zA-Z]{2})?\d{1,10}$', payload):
            return None, ""
        return internal_type, payload.upper()

    # 9. GEOSITE
    if internal_type == 'geosite':
        return internal_type, payload.lower()

    # 10. GEOIP
    if internal_type == 'geoip':
        return internal_type, payload.lower()

    return internal_type, payload


def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
    """纯文本分流：识别前缀，卡尺校验，动态 TLD 划分 suffix 与 full。"""
    if not line:
        return None, ""

    # 1. 前缀处理管道剥离显式前缀
    is_explicit_suffix, clean_val = strip_domain_prefix(line)

    # 2. 拒绝隐式通配符
    if '*' in clean_val:
        return None, ""

    # 3. 短路 IP / CIDR 校验
    first_char = clean_val[0] if clean_val else ""
    if first_char.isdigit() or first_char == '[' or ':' in clean_val or '/' in clean_val:
        ip_type, checked_ip = _is_exact_ip(clean_val)
        if ip_type is not None:
            if is_explicit_suffix:
                return None, ""
            return ip_type, checked_ip

    # 4. FQDN 域名正则卡尺（显式开启 allow_single_label=True）
    exact_domain = _is_exact_domain(clean_val, allow_single_label=True)
    if not exact_domain:
        return None, ""

    # 5. 公共后缀黑名单拦截
    if not is_explicit_suffix and exact_domain in PUBLIC_SUFFIX_BLACKLIST:
        return None, ""
    
    # 6. 显式前缀直接弹回为 suffix
    if is_explicit_suffix:
        return 'suffix', exact_domain

    # 7. 单段裸域名（如 google, apple, cn）默认判定为 suffix 匹配
    parts = exact_domain.split('.')
    num_parts = len(parts)
    if num_parts == 1:
        return 'suffix', exact_domain

    # 8. 动态 TLD 深度计算（多段域名）
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
    """解析 AdGuard 格式规则 (|| 代表 suffix，| 代表 full)。"""  
    if not line:
        return None, ""

    core_content = line.split('$')[0].split('^')[0].strip().rstrip('|')

    if core_content.startswith('||'):
        internal_type = 'suffix'
        raw_payload = core_content[2:].strip()
    elif core_content.startswith('|'):
        internal_type = 'full'
        raw_payload = core_content[1:].strip()
    else:
        return None, ""

    if '://' in raw_payload:
        raw_payload = raw_payload.split('://', 1)[1]

    if '/' in raw_payload:
        parts = raw_payload.split('/', 1)
        if parts[1].strip():
            return None, ""
        raw_payload = parts[0].strip()

    exact_domain = _is_exact_domain(
        raw_payload, 
        allow_single_label=(internal_type == 'suffix')
    )
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
