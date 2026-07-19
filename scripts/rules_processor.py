# -*- coding: utf-8 -*-
import re
import logging
from typing import Tuple, Optional, Dict, Set, List

# 配置基础日志输出
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


# ==================== 核心数据矩阵与配置 ====================

# IP 正则：精准匹配 IPv4 及可选掩码
IPV4_REGEX = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
)

# IP 正则：兼容标准、压缩 IPv6 及可选掩码
IPV6_REGEX = re.compile(
    r'^\[?([0-9a-fA-F]{1,4}:){1,7}:?([0-9a-fA-F]{1,4})?\]?(\/(12[0-8]|1[0-1]\d|[1-9]?\d))?$'
)

# 公共后缀黑名单矩阵：用于判定无类型前缀的纯文本域名行是否默认归类为后缀匹配 (suffix)
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
    'fj.cn', 'gd.cn', 'gs.cn', 'gx.cn', 'gz.cn', 'ha.cn', 'hb.cn', 'he.cn', 'hi.cn', 'hl.cn',
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

# 规则归一化映射字典
_GROUPS = {
    'remove':    {'REMOVE'},
    'process':   {'PROCESS-NAME', 'PROCESS_NAME', 'PROCESS'},
    'port':      {'DST-PORT', 'DEST-PORT', 'PORT'},
    'full':      {'DOMAIN', 'HOST', 'FULL'},
    'suffix':    {'DOMAIN-SUFFIX', 'HOST-SUFFIX', 'DOMAIN_SUFFIX', 'SUFFIX'},
    'keyword':   {'DOMAIN-KEYWORD', 'HOST-KEYWORD', 'DOMAIN_KEYWORD', 'KEYWORD'},
    'ip':        {'IP-CIDR', 'IP'},
    'ip6':       {'IP-CIDR6', 'IP6-CIDR', 'IP6'}, 
    'useragent': {'USER-AGENT', 'USERAGENT'},
    'wildcard':  {'DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD'},
    'regex':     {'DOMAIN-REGEX', 'DOMAIN_REGEX', 'REGEX'}
}

SOURCE_KEYS = list(_GROUPS.keys())
RULE_MAP = {rule_name: target_cat for target_cat, rule_sets in _GROUPS.items() for rule_name in rule_sets}


# ==================== 内部私有辅助工具集 ====================

def _parse_ip_string(raw_str: str) -> Tuple[Optional[str], str]:
    """剥离IP括号和端口，识别IPv4/IPv6类型"""
    if ']:' in raw_str:
        cleaned = raw_str.split(']:')[0].lstrip('[')
    else:
        cleaned = raw_str.strip('[]')
    
    ip_body = cleaned.split('/')[0]
    
    if ':' in ip_body and '/' not in cleaned and not IPV6_REGEX.match(ip_body):
        parts = ip_body.split(':')
        if parts[-1].isdigit():
            ip_body = ':'.join(parts[:-1])
            cleaned = ip_body
            
    if IPV4_REGEX.match(ip_body):
        return 'ip', cleaned
    if IPV6_REGEX.match(ip_body):
        return 'ip6', cleaned.lower()
        
    return None, raw_str


def _clean_domain_syntax(domain: str) -> Optional[str]:
    """剥离域名端口并转化为Punycode"""
    domain = domain.rstrip('.').lstrip('+*.')
    if ':' in domain and ']' not in domain:
        parts = domain.split(':')
        if len(parts) == 2 and parts[1].split('/')[0].isdigit():
            domain = parts[0]
            
    if not domain.isascii():
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return None
            
    return domain.lower()

# ==================== 主流水线总入口 ====================

def execute_rules_pipeline(local_raw_lines: List[str], remote_raw_lines: List[str]) -> Dict[str, Set[str]]:
    """主执行流水线：解析、去重、合并与优化"""
    logging.info(f"开始处理规则，本地: {len(local_raw_lines)} 行，远程: {len(remote_raw_lines)} 行")
    
    local_rules = process_raw_lines_batch(local_raw_lines, SOURCE_KEYS)
    remote_rules = process_raw_lines_batch(remote_raw_lines, SOURCE_KEYS)
    logging.info("规则基础解析完成")
    
    merged_rules = merge_and_sovereignty_filter(local_rules, remote_rules, SOURCE_KEYS)
    logging.info("高优先级本地资产过滤与合并完成")
    
    optimize_domains(merged_rules)
    logging.info("树状折叠去重优化完成")
    
    return merged_rules

#  ==================== 核心解析与格式收拢断言 ====================

def filter_raw_line(line: str) -> Optional[str]:
    """剔除注释符号和多余前缀"""
    line = line.split('#')[0].split('//')[0].split(';')[0].strip()
    if not line or line.lower() == 'payload:':
        return None
    if line.startswith('- '):
        line = line[2:].strip()
    return line if line else None


def normalize_rule_line(raw_payload: str, internal_type: Optional[str]) -> Optional[str]:
    """根据类型执行载荷的强校验与格式收拢"""
    payload = raw_payload.strip().strip("'").strip('"').strip()
    if not payload:
        return None

    if internal_type == 'remove':
        ip_type, parsed_ip = _parse_ip_string(payload)
        if ip_type:
            payload = parsed_ip if '/' in parsed_ip else f"{parsed_ip}/{'128' if ip_type == 'ip6' else '32'}"
        else:
            payload = _clean_domain_syntax(payload)
            
    elif internal_type in ['full', 'suffix', 'keyword']:
        payload = _clean_domain_syntax(payload)

    elif internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        parts = [p.strip() for p in payload.split('-') if p.strip()]
        payload = '-'.join(parts) if parts else None

    elif internal_type in ['ip', 'ip6']:
        ip_type, parsed_ip = _parse_ip_string(payload)
        if not ip_type:
            return None
        internal_type = ip_type 
        payload = parsed_ip if '/' in parsed_ip else f"{parsed_ip}/{'128' if internal_type == 'ip6' else '32'}"

    return payload


def parse_line(line: str) -> Tuple[Optional[str], str]:
    """智能路由单行文本至对应解析器"""
    clean_line = filter_raw_line(line)
    if not clean_line:
        return None, ""

    if clean_line.startswith('|'):
        return parse_adguard_rule(clean_line)
        
    head, _, _ = clean_line.partition(',')
    head = head.strip()

    if head.upper() in RULE_MAP:
        return parse_standard_rule(clean_line)
        
    return parse_pure_text_rule(clean_line)


def parse_standard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析标准前缀声明的规则（如 DOMAIN-SUFFIX）"""
    parts = [x.strip() for x in line.split(',')]
    if not parts:
        return None, ""

    tag = parts[0].upper()
    internal_type = RULE_MAP[tag]

    if internal_type in ['regex', 'wildcard', 'useragent']:
        raw_payload = ','.join(parts[1:-1]).strip() if len(parts) > 2 else (parts[1] if len(parts) >= 2 else "")
        return internal_type, raw_payload

    raw_payload = parts[1] if len(parts) >= 2 else ""
    if not raw_payload:
        return None, ""

    if internal_type in ['full', 'suffix', 'keyword'] and (IPV4_REGEX.match(raw_payload) or IPV6_REGEX.match(raw_payload)):
        return None, ""
        
    if internal_type in ['full', 'suffix', 'keyword', 'remove', 'process']:
        if any(c in raw_payload for c in [' ', '@', '=', '%', '&', ';']):
            return None, ""
            
    final_payload = normalize_rule_line(raw_payload, internal_type)
    if not final_payload:
        return None, ""

    if internal_type == 'ip' and IPV6_REGEX.match(final_payload.split('/')[0]):
        internal_type = 'ip6'

    return internal_type, final_payload


def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
    """无前缀纯文本规则嗅探"""
    if any(c in line for c in ['?', '(', ')', '|', '^', '$', '\\']):
        return None, ""

    if '*' in line and not (line.startswith('*.') or line.startswith('+.')):
        return None, ""

    is_explicit_suffix = line.startswith('+.') or line.startswith('*.') or line.startswith('.')
    clean_val = line.lstrip('+*.')
    if not clean_val or clean_val.isdigit():
        return None, ""

    ip_type, _ = _parse_ip_string(clean_val)
    if ip_type:
        internal_type = ip_type
    else:
        if any(c in clean_val for c in [' ', '/', '@', '=', '%', '&', ';']):
            return None, ""
            
        clean_val_lower = clean_val.lower()
        is_public_suffix = (
            clean_val_lower in PUBLIC_SUFFIX_BLACKLIST or 
            any(clean_val_lower.endswith(f'.{suf}') for suf in PUBLIC_SUFFIX_BLACKLIST)
        )

        internal_type = 'suffix' if (is_explicit_suffix or is_public_suffix) else 'full'

    final_payload = normalize_rule_line(clean_val, internal_type)
    return (internal_type, final_payload) if final_payload else (None, "")


def parse_adguard_rule(line: str) -> Tuple[Optional[str], str]:
    """解析简易 AdGuard / uBlock Filter 格式规则"""
    core_content = line.split('^')[0].strip()
    for prefix, internal_type in [('||', 'suffix'), ('|', 'full')]:
        if core_content.startswith(prefix):
            raw_payload = core_content[len(prefix):].strip()
            break
    else:
        return None, "" 

    if not raw_payload or any(c in raw_payload for c in [' ', '@', '=', '%', '&', ';', '/']):
        return None, ""

    final_payload = normalize_rule_line(raw_payload, internal_type)
    return (internal_type, final_payload) if final_payload else (None, "")

#  ==================== 批量控制、主权合并与树状剪枝优化 ====================

def process_raw_lines_batch(lines: List[str], rule_keys: List[str]) -> Dict[str, Set[str]]:
    """批量分发解析，Set结构天然去重"""
    parsed_rules = {k: set() for k in rule_keys}
    for line in lines:
        r_type, payload = parse_line(line)  
        if payload and r_type in parsed_rules:
            parsed_rules[r_type].add(payload)
    return parsed_rules


def merge_and_sovereignty_filter(local_rules: Dict[str, Set[str]], remote_rules: Dict[str, Set[str]], rule_keys: List[str]) -> Dict[str, Set[str]]:
    """合并规则，本地资产和remove排除项拥有最高主权"""
    merged = {}
    local_all_assets = set()
    local_remove = set(local_rules.get('remove', [])) if local_rules else set()
    
    if local_rules:
        for r_type in rule_keys:
            if r_type != 'remove' and r_type in local_rules:
                local_all_assets.update(local_rules[r_type])

    for r_type in rule_keys:
        local_set = set(local_rules.get(r_type, [])) if local_rules else set()
        remote_set = set(remote_rules.get(r_type, [])) if remote_rules else set()
        
        if r_type != 'remove':
            remote_set -= local_all_assets
            combined_set = local_set | remote_set
            combined_set -= local_remove            
            merged[r_type] = combined_set
        else:
            merged['remove'] = local_set | remote_set
            
    return merged


def optimize_domains(rules: Dict[str, Set[str]]) -> None:
    """高阶树状子域名折叠去重，剪枝冗余子节点"""
    if not isinstance(rules, dict) or 'suffix' not in rules or 'full' not in rules: 
        return
        
    raw_suffixes = {s for s in rules['suffix'] if s and '.' in s}
    optimized_suffixes = set()
    raw_fulls = {f for f in rules['full'] if f}
    optimized_fulls = set()

    for suf in sorted(list(raw_suffixes), key=len):
        parts = suf.split('.')
        if any('.'.join(parts[i:]) in optimized_suffixes for i in range(1, len(parts))):
            continue
        optimized_suffixes.add(suf)

    for f_dom in raw_fulls:
        if f_dom in optimized_suffixes:
            continue
        parts = f_dom.split('.')
        if any('.'.join(parts[i:]) in optimized_suffixes for i in range(1, len(parts))):
            continue
        optimized_fulls.add(f_dom)

    rules['suffix'] = optimized_suffixes
    rules['full'] = optimized_fulls
