# -*- coding: utf-8 -*-
import re
from typing import Tuple, Optional

# IPv4 正则：精确匹配 4 段数字边界以及可选的 CIDR 网段 (/0-/32)
IPV4_REGEX = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
)
# IPv6 正则：匹配标准及简写 IPv6 格式以及可选的 CIDR 网段 (/0-/128)
IPV6_REGEX = re.compile(
    r'^\[?([0-9a-fA-F]{1,4}:){1,7}:?([0-9a-fA-F]{1,4})?\]?(\/(12[0-8]|1[0-1]\d|[1-9]?\d))?$'
)

# 过滤辅助黑名单：用于将无明确前缀的主流域名默认归类为后缀匹配 (suffix)
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

# 外部规则关键字到内部统一类型的映射组
_GROUPS = {
    'remove': {'REMOVE'},
    'process': {'PROCESS-NAME', 'PROCESS_NAME', 'PROCESS'},
    'port': {'DST-PORT', 'DEST-PORT', 'PORT'},
    'full': {'DOMAIN', 'HOST', 'FULL'},
    'suffix': {'DOMAIN-SUFFIX', 'HOST-SUFFIX', 'DOMAIN_SUFFIX', 'SUFFIX'},
    'keyword': {'DOMAIN-KEYWORD', 'HOST-KEYWORD', 'DOMAIN_KEYWORD', 'KEYWORD'},
    'ip': {'IP-CIDR', 'IP'},
    'ip6': {'IP-CIDR6', 'IP6-CIDR', 'IP6'}, 
    'useragent': {'USER-AGENT', 'USERAGENT'},
    'wildcard': {'DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD'},
    'regex': {'DOMAIN-REGEX', 'DOMAIN_REGEX', 'REGEX'}
}

source_keys = list(_GROUPS.keys())
RULE_MAP = {rule: category for category, rules in _GROUPS.items() for rule in rules}

def execute_rules_pipeline(local_raw_lines: list, remote_raw_lines: list) -> dict:
    local_rules = process_raw_lines_batch(local_raw_lines, source_keys)
    remote_rules = process_raw_lines_batch(remote_raw_lines, source_keys)
    
    merged_rules = merge_and_sovereignty_filter(local_rules, remote_rules, source_keys)
    optimize_domains(merged_rules)
    
    return merged_rules
    
def filter_raw_line(line: str) -> Optional[str]:
    """
    基础清洗：剥离注释（#, //, ;）以及前缀标识符（- ）
    """
    line = line.split('#')[0].split('//')[0].split(';')[0].strip()
    if not line or line.lower() == 'payload:':
        return None
    if line.startswith('- '):
        line = line[2:].strip()
    return line if line else None


def normalize_rule_line(raw_payload: str, internal_type: Optional[str]) -> Optional[str]:
    """
    核心清洗与标准化：处理域名后缀符号、端口剥离、IDNA(Punycode)转码、IP掩码补全
    """
    payload = raw_payload.strip().strip("'").strip('"').strip()
    if not payload:
        return None

    if internal_type in ['full', 'suffix', 'keyword']:
        payload = payload.rstrip('.')
        payload = payload.lstrip('+*.') 
        
        if ':' in payload and ']' not in payload:
            if payload.count(':') == 1:
                host, port_part = payload.split(':')
                if port_part.split('/')[0].isdigit():
                    payload = host

        if not payload.isascii():
            try:
                payload = payload.encode('idna').decode('ascii')
            except Exception:
                return None
        payload = payload.lower()

    elif internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        clean_parts = [p.strip() for p in payload.split('-') if p.strip()]
        if not clean_parts:
            return None
        payload = '-'.join(clean_parts)

    elif internal_type in ['ip', 'ip6']:
        if internal_type == 'ip6' and ']' in payload:
            if ']:' in payload:
                payload = payload.split(']:')[0].lstrip('[')
            else:
                payload = payload.strip('[]')
        else:
            payload = payload.strip('[]')

        if internal_type == 'ip' and ':' in payload and '/' not in payload:
            if payload.count(':') == 1:
                ip_part, port_part = payload.split(':')
                if port_part.isdigit():
                    payload = ip_part
                    
        if '/' not in payload:
            payload = f"{payload}/128" if internal_type == 'ip6' else f"{payload}/32"

    return payload
    
def parse_line(line: str) -> Tuple[Optional[str], str]:
    """
    规则解析主入口：利用特征分流机制，优雅实现多格式自适应解析
    """
    clean_line = filter_raw_line(line)
    if not clean_line:
        return None, ""

    if clean_line.startswith('|'):
        return parse_adguard_rule(clean_line)
        
    head, _, _ = clean_line.partition(',')
    head = head.strip()

    if head.upper() in RULE_MAP:
        return parse_standard_rule(clean_line)
        
    return parse_pure_text_rule(head)


def parse_standard_rule(line: str) -> Tuple[Optional[str], str]:
    """
    解析带标签的标准逗号规则：精准提取 Payload，完美剥离尾部策略组，并兼容防错切机制
    """
    parts = [x.strip() for x in line.split(',')]
    if not parts:
        return None, ""

    tag = parts[0].upper()
    internal_type = RULE_MAP[tag]

    if internal_type in ['regex', 'wildcard', 'useragent']:
        if len(parts) > 2:
            raw_payload = ','.join(parts[1:-1]).strip()
        else:
            raw_payload = parts[1] if len(parts) >= 2 else ""
        return internal_type, raw_payload

    raw_payload = parts[1] if len(parts) >= 2 else ""
    if not raw_payload:
        return None, ""

    if internal_type in ['full', 'suffix', 'keyword', 'remove', 'process']:
        if any(c in raw_payload for c in [' ', '@', '=', '%', '&', ';']):
            return None, ""
            
    final_payload = normalize_rule_line(raw_payload, internal_type)
    if not final_payload:
        return None, ""

    return internal_type, final_payload

def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
    """
    解析不带标签的纯文本规则：通过特征识别自动归类为 IP、IPv6、Suffix 或 Full
    """
    if any(c in line for c in ['?', '(', ')', '|', '^', '$', '\\']):
        return None, ""

    if '*' in line and not (line.startswith('*.') or line.startswith('+.')):
        return None, ""

    is_explicit_suffix = line.startswith('+.') or line.startswith('*.') or line.startswith('.')
    clean_val = line.lstrip('+*.')
    if not clean_val or clean_val.isdigit():
        return None, ""

    val_for_ip_check = clean_val
    if ':' in clean_val and ']' not in clean_val:
        ports_split = clean_val.split(':')
        if len(ports_split) == 2 and ports_split[1].isdigit():
            val_for_ip_check = ports_split[0]
    elif ']:' in clean_val:
        val_for_ip_check = clean_val.split(']:')[0].lstrip('[')
    else:
        val_for_ip_check = clean_val.strip('[]').split('/')[0]

    if IPV4_REGEX.match(val_for_ip_check) or IPV4_REGEX.match(clean_val.split('/')[0]):
        internal_type = 'ip'
    elif IPV6_REGEX.match(val_for_ip_check) or IPV6_REGEX.match(clean_val.split('/')[0].strip('[]')):
        internal_type = 'ip6'
    else:
        if any(c in clean_val for c in [' ', '/', '@', '=', '%', '&', ';']):
            return None, ""

        if is_explicit_suffix or ('.' in clean_val and clean_val.split('.')[-1] in PUBLIC_SUFFIX_BLACKLIST):
            internal_type = 'suffix'
        else:
            internal_type = 'full'

    final_payload = normalize_rule_line(clean_val, internal_type)
    if not final_payload:
        return None, ""

    return internal_type, final_payload

def parse_adguard_rule(line: str) -> Tuple[Optional[str], str]:
    """
    解析 AdGuard 语法：将 || 映射为 suffix，| 映射为 full，剥离 ^ 断言符
    """
    core_content = line.split('^')[0].strip()
    for prefix, internal_type in [('||', 'suffix'), ('|', 'full')]:
        if core_content.startswith(prefix):
            raw_payload = core_content[len(prefix):].strip()
            break
    else:
        return None, "" 

    if not raw_payload or any(c in raw_payload for c in ' @=%&;/'):
        return None, ""

    final_payload = normalize_rule_line(raw_payload, internal_type)
    return (internal_type, final_payload) if final_payload else (None, "")

def process_raw_lines_batch(lines: list, rule_keys: list) -> dict:
    """
    批量处理入口：将原始文本列表解析并按类别归入集合（Set）中自动去重
    """
    parsed_rules = {k: set() for k in rule_keys}
    for line in lines:
        r_type, payload = parse_line(line)  
        if payload and r_type in parsed_rules:
            parsed_rules[r_type].add(payload)
    return parsed_rules


def merge_and_sovereignty_filter(local_rules: dict, remote_rules: dict, rule_keys: list) -> dict:

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


def optimize_domains(rules: dict, protected_parents: set = None) -> None:
    
    if not isinstance(rules, dict) or 'suffix' not in rules or 'full' not in rules: 
        return
        
    is_list_output = isinstance(rules['suffix'], list)
    suffixes = set(rules['suffix'])
    raw_fulls = set(rules['full'])
    optimized_fulls = set()
    
    protected = set(protected_parents) if protected_parents else set()

    for f_dom in raw_fulls:
        if f_dom in suffixes:
            continue
            
        parts = f_dom.split('.')
        is_folded = False
       
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            
            if parent in protected:
                break
                
            if parent in suffixes:
                is_folded = True
                break
                
        if not is_folded:
            optimized_fulls.add(f_dom)

    if is_list_output:
        rules['suffix'] = sorted(list(suffixes))
        rules['full'] = sorted(list(optimized_fulls))
    else:
        rules['suffix'] = suffixes
        rules['full'] = optimized_fulls
