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

# 规则内部归一化类型映射表
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


# 执行规则处理流水线主入口
def execute_rules_pipeline(local_raw_lines: list, remote_raw_lines: list) -> dict:
    local_rules = process_raw_lines_batch(local_raw_lines, source_keys)
    remote_rules = process_raw_lines_batch(remote_raw_lines, source_keys)
    
    merged_rules = merge_and_sovereignty_filter(local_rules, remote_rules, source_keys)
    optimize_domains(merged_rules)
    
    return merged_rules


# 过滤原始文本行中的注释与多余前缀
def filter_raw_line(line: str) -> Optional[str]:
    line = line.split('#')[0].split('//')[0].split(';')[0].strip()
    if not line or line.lower() == 'payload:':
        return None
    if line.startswith('- '):
        line = line[2:].strip()
    return line if line else None


# 核心规则清洗与格式归一化转换
def normalize_rule_line(raw_payload: str, internal_type: Optional[str]) -> Optional[str]:
    payload = raw_payload.strip().strip("'").strip('"').strip()
    if not payload:
        return None

    # 对 REMOVE 规则执行自愈分流（自动适配 IP 或域名清洗流程）
    if internal_type == 'remove':
        temp_payload = payload.strip('[]')
        val_for_ip_check = temp_payload.split('/')[0].split(':')[0]
        
        if IPV4_REGEX.match(val_for_ip_check) or IPV4_REGEX.match(temp_payload.split('/')[0]):
            payload = temp_payload if '/' in temp_payload else f"{temp_payload}/32"
        elif IPV6_REGEX.match(val_for_ip_check) or IPV6_REGEX.match(temp_payload.split('/')[0].strip('[]')):
            payload = temp_payload.lower() if '/' in temp_payload else f"{temp_payload.lower()}/128"
        else:
            payload = payload.rstrip('.')
            payload = payload.lstrip('+*.') 
            if not payload.isascii():
                try:
                    payload = payload.encode('idna').decode('ascii')
                except Exception:
                    return None
            payload = payload.lower()

    # 域名类规则标准化（移除前缀符号、端口剥离并转换为 Punycode）
    elif internal_type in ['full', 'suffix', 'keyword']:
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

    # 端口规则规范化
    elif internal_type == 'port':
        payload = payload.replace('(', '').replace(')', '').replace(':', '-')
        clean_parts = [p.strip() for p in payload.split('-') if p.strip()]
        if not clean_parts:
            return None
        payload = '-'.join(clean_parts)

    # IP 规则标准化（剥离括号、自动补全 CIDR 掩码并对 IPv6 执行小写转换）
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

        # 强制将所有 IPv6 地址归一化为纯小写，避免 A-F 产生去重漏洞
        if internal_type == 'ip6':
            payload = payload.lower()

    return payload


# 解析单行规则并识别、分发至对应的格式解析器
def parse_line(line: str) -> Tuple[Optional[str], str]:
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


# 解析标准声明前缀的逗号分隔规则
def parse_standard_rule(line: str) -> Tuple[Optional[str], str]:
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

    if internal_type in ['full', 'suffix', 'keyword'] and (
        IPV4_REGEX.match(raw_payload.split('/')[0]) or 
        IPV6_REGEX.match(raw_payload.split('/')[0].strip('[]'))
    ):
        return None, ""

    if internal_type == 'ip' and IPV6_REGEX.match(raw_payload.split('/')[0].strip('[]')):
        internal_type = 'ip6'
        
    if internal_type in ['full', 'suffix', 'keyword', 'remove', 'process']:
        if any(c in raw_payload for c in [' ', '@', '=', '%', '&', ';']):
            return None, ""
            
    final_payload = normalize_rule_line(raw_payload, internal_type)
    if not final_payload:
        return None, ""

    return internal_type, final_payload


# 解析无声明前缀的纯文本格式规则
def parse_pure_text_rule(line: str) -> Tuple[Optional[str], str]:
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

        # 将 TLD 后缀强制小写后再与后缀黑名单匹配
        if is_explicit_suffix or ('.' in clean_val and clean_val.split('.')[-1].lower() in PUBLIC_SUFFIX_BLACKLIST):
            internal_type = 'suffix'
        else:
            internal_type = 'full'

    final_payload = normalize_rule_line(clean_val, internal_type)
    if not final_payload:
        return None, ""

    return internal_type, final_payload


# 解析简易 AdGuard / uBlock Filter 格式的规则
def parse_adguard_rule(line: str) -> Tuple[Optional[str], str]:
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


# 批量处理并解析原始文本规则集
def process_raw_lines_batch(lines: list, rule_keys: list) -> dict:
    parsed_rules = {k: set() for k in rule_keys}
    for line in lines:
        r_type, payload = parse_line(line)  
        if payload and r_type in parsed_rules:
            parsed_rules[r_type].add(payload)
    return parsed_rules


# 合并本地/远程规则集，执行高优先级本地排除和去重过滤
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


# 执行域名向父级后缀的嵌套包含折叠优化（树状去重）
def optimize_domains(rules: dict) -> None:
    if not isinstance(rules, dict) or 'suffix' not in rules or 'full' not in rules: 
        return
        
    raw_suffixes = set(rules['suffix'])
    optimized_suffixes = set()
    raw_fulls = set(rules['full'])
    optimized_fulls = set()

    # Suffix 内部互相折叠（从小到大排序，保留顶级规则）
    sorted_suffixes = sorted(list(raw_suffixes), key=len)
    for suf in sorted_suffixes:
        parts = suf.split('.')
        is_folded = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in optimized_suffixes:
                is_folded = True
                break
        if not is_folded:
            optimized_suffixes.add(suf)

    # 精确域名 Full 向已优化的 Suffix 后缀折叠
    for f_dom in raw_fulls:
        if f_dom in optimized_suffixes:
            continue
            
        parts = f_dom.split('.')
        is_folded = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in optimized_suffixes:
                is_folded = True
                break
                
        if not is_folded:
            optimized_fulls.add(f_dom)

    rules['suffix'] = optimized_suffixes
    rules['full'] = optimized_fulls
