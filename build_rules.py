# -*- coding: utf-8 -*-
import os
import json
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# 1. 常量与全局配置初始化
# ==========================================
RULESET_BASE_DIR = 'ruleset'
SOURCE_DIR = os.path.join(RULESET_BASE_DIR, 'source')
SHADOWROCKET_DIR = os.path.join(RULESET_BASE_DIR, 'shadowrocket')
QUANTUMULTX_DIR = os.path.join(RULESET_BASE_DIR, 'quantumultx')
MIHOMO_DIR = os.path.join(RULESET_BASE_DIR, 'mihomo')
PAC_DIR = os.path.join(RULESET_BASE_DIR, 'pac')
SINGBOX_DIR = os.path.join(RULESET_BASE_DIR, 'singbox')

# 确保所有基础目录存在
for d in [RULESET_BASE_DIR, SOURCE_DIR, SHADOWROCKET_DIR, QUANTUMULTX_DIR, MIHOMO_DIR, PAC_DIR, SINGBOX_DIR]:
    if not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

RULESET_JSON_PATH = os.path.join(RULESET_BASE_DIR, 'ruleset.json')
if not os.path.exists(RULESET_JSON_PATH):
    with open(RULESET_JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump([], f, indent=2, ensure_ascii=False)

try:
    with open(RULESET_JSON_PATH, 'r', encoding='utf-8') as f:
        FILE_POLICY_ROUTER = json.load(f)
except json.JSONDecodeError as e:
    print(f"\n❌ ruleset.json [{e.lineno}:{e.colno}] -> {e.msg}\n")
    import sys
    sys.exit(1)   

# ==========================================
# 2. 正则表达式与静态映射数据
# ==========================================
# 严格限制作用域，避免无谓的全局变量污染
IPV4_REGEX = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
)
IPV6_REGEX = re.compile(
    r'^\[?([0-9a-fA-F]{1,4}:){1,7}:?([0-9a-fA-F]{1,4})?\]?(\/(12[0-8]|1[0-1]\d|[1-9]?\d))?$'
)
DOMAIN_PATTERN = re.compile(r'^(?!-)[a-z0-9\-]+(?<!-)(\.(?!-)[a-z0-9\-]+(?<!-))+$')

PUBLIC_SUFFIX_BLACKLIST = {
    'com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'arpa', 'biz', 'info', 'name', 'pro',
    'app', 'dev', 'shop', 'club', 'top', 'xyz', 'vip', 'fun', 'site', 'online', 'tech', 'store',
    'work', 'live', 'link', 'icu', 'ltd', 'art', 'blog', 'news', 'wiki', 'chat', 'space', 'me',
    'cn', 'hk', 'tw', 'mo', 'jp', 'kr', 'sg', 'my', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'ru',
    'ai', 'io', 'co', 'so', 'to', 'do', 'in', 'cc', 'tv', 'la', 'fm', 'am', 'im', 'gg',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'mil.cn', 'ac.cn', 'ah.cn', 'bj.cn', 'cq.cn',
    'fj.cn', 'gd.cn', 'gs.cn', 'gx.cn', 'gz.cn', 'ha.cn', 'hb.cn', 'he.cn', 'hi.cn', 'hl.cn',
    'hn.cn', 'jl.cn', 'js.cn', 'jx.cn', 'ln.cn', 'nm.cn', 'nx.cn', 'qh.cn', 'sc.cn', 'sd.cn',
    'sh.cn', 'sn.cn', 'sx.cn', 'tj.cn', 'xj.cn', 'xz.cn', 'yn.cn', 'zj.cn',
    'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk', 'idv.hk',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw', 'idv.tw', 'club.tw',
    'com.mo', 'net.mo', 'org.mo', 'gov.mo', 'edu.mo',
    'co.uk', 'me.uk', 'org.uk', 'ltd.uk', 'plc.uk', 'gov.uk', 'sch.uk',
    'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp', 'ed.jp', 'ad.jp',
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'mil.kr',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'co.id', 'web.id',
    'com.au', 'net.au', 'org.au', 'asn.au', 'id.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz',
    'com.br', 'net.br', 'org.br', 'gov.br', 'co.za', 'web.za'
}

RULE_TYPE_MAP = {
    'DOMAIN': 'full', 'HOST': 'full', 'FULL': 'full', 'DOMAIN-FULL': 'full',
    'DOMAIN-SUFFIX': 'suffix', 'SUFFIX': 'suffix', 'HOST-SUFFIX': 'suffix', 'DOMAIN_SUFFIX': 'suffix',
    'DOMAIN-KEYWORD': 'keyword', 'KEYWORD': 'keyword', 'HOST-KEYWORD': 'keyword', 'DOMAIN_KEYWORD': 'keyword',
    
    'DOMAIN-WILDCARD': 'wildcard', 'HOST-WILDCARD': 'wildcard', 'WILDCARD': 'wildcard', 
    'DOMAIN-REGEX': 'regex', 'DOMAIN_REGEX': 'regex', 'REGEX': 'regex', 
    
    'IP-CIDR': 'ip', 'IP': 'ip',
    'IP-CIDR6': 'ip6', 'IP6': 'ip6', 'IP6-CIDR': 'ip6',
    
    'PROCESS-NAME': 'process', 'PROCESS': 'process', 'PROCESS_NAME': 'process',
    'DST-PORT': 'port', 'DEST-PORT': 'port', 'PORT': 'port', 
    'USER-AGENT': 'useragent', 'USERAGENT': 'useragent'
}


# ==========================================
# 3. 基础工具与辅助清洗函数
# ==========================================
def is_ip_centric_name(name):
    name_lower = name.lower()
    if name_lower in ['ip', 'ipcidr']: return True
    return bool(re.search(r'(^|[_0-9-])ip([_0-9-]|$)', name_lower))

def is_truthy_cfg(policy, key):
    val = policy.get(key)
    return val is True or str(val).lower() == 'true'
    
def parse_target_config(policy, field_name, default_base_name):
    val = policy.get(field_name)
    if val is False or str(val).lower() == 'false':
        return False, None
    if val is None or val == '' or val is True or str(val).lower() == 'true':
        return True, default_base_name
    return True, str(val).strip()
    
def get_smart_base_name(name, policy, existing_names):
    if name.strip():
        base = name.strip().lower() 
    else:
        url = policy.get('url', '')
        first_url = url[0] if isinstance(url, list) and url else url
        base = 'untitled_unknown'
        if first_url:
            try:
                last_part = first_url.split('/')[-1]
                extracted = os.path.splitext(last_part)[0]
                if extracted.strip():
                    base = extracted.strip().lower() 
            except Exception:
                pass
                
    orig_base = base
    counter = 1
    while base in existing_names:
        base = f"{orig_base}_{counter}"
        counter += 1
    return base

def try_punycode_encode(domain_str):
    if domain_str.isascii():
        return domain_str
    try:
        return domain_str.encode('idna').decode('ascii').lower()
    except Exception:
        return None

def has_invalid_domain_chars(domain_str):
    return any(c in domain_str for c in [' ', '/', '?', '@', ':', '=', '%', '&', ';', '[', ']', '(', ')'])

def validate_ip_mask(ip_str, is_ipv6=False):
    if '/' in ip_str:
        try:
            parts = ip_str.split('/')
            mask = int(parts[1])
            return 0 <= mask <= 128 if is_ipv6 else 0 <= mask <= 32
        except Exception:
            return False
    return True

def ensure_ip_mask(ip_str, is_ipv6=False):
    if '/' in ip_str: return ip_str
    return f"{ip_str}/128" if is_ipv6 else f"{ip_str}/32"

def extract_combined_cidrs(rules_dict):
    ipv4_list = [ensure_ip_mask(i, False) for i in rules_dict.get('ip', [])]
    ipv6_list = [ensure_ip_mask(i, True) for i in rules_dict.get('ip6', [])]
    return sorted(list(set(ipv4_list + ipv6_list)))

def convert_wildcard_to_regex(wildcard_str):
    if '*' not in wildcard_str and '?' not in wildcard_str:
        return f"^{re.escape(wildcard_str)}$"
    escaped = re.escape(wildcard_str)
    r_val = escaped.replace(r'\*', '.*').replace(r'\?', '.')
    while '.*.*' in r_val:
        r_val = r_val.replace('.*.*', '.*')
    return f"^{r_val}$"

def parse_ports_for_singbox(port_set):
    p_list, p_range = [], []
    for p in port_set:
        if isinstance(p, tuple):
            p = str(p[0]) if p else ""
        else:
            p = str(p)
        p = p.strip()
        if not p: continue

        if '-' in p: 
            p_range.append(p.replace('-', ':'))
        elif ':' in p: 
            p_range.append(p)
        else: 
            try:
                p_list.append(int(p))
            except ValueError:
                pass 
    return sorted(p_list), sorted(p_range)

# ==========================================
# 4. 核心规则树清洗与高级优化算法
# ==========================================
def clean_and_parse_line(line):
    line = line.strip()
    if not line or line.startswith(('#', '//', ';')) or line == 'payload:':
        return None, None
    if line.startswith('-'):
        line = line.lstrip('-').strip()
    line = line.strip("'").strip('"').strip()
    
    if not line: return None, None

    if ',' in line:
        possible_tag = line.split(',')[0].strip().upper()
        internal_type = RULE_TYPE_MAP.get(possible_tag)
        if not internal_type or possible_tag in ['AND', 'OR', 'NOT']:
            return None, None
            
        p1, p2 = [x.strip() for x in line.split(',', 1)]
        if possible_tag not in ['DOMAIN-REGEX', 'REGEX', 'USER-AGENT', 'USERAGENT']:
            p2 = p2.split('#')[0].split('//')[0].strip()

        if internal_type == 'port':
            p2_clean = p2.lower().replace('(', '').replace(')', '').strip()
            if ',' in p2_clean: p2_clean = p2_clean.split(',')[0].strip()
            if ':' in p2_clean or '-' in p2_clean:
                splitter = ':' if ':' in p2_clean else '-'
                s, e = p2_clean.split(splitter, 1)
                try: 
                    return 'port', f"{int(s.strip())}-{int(e.strip())}"
                except ValueError: return None, None
            else:
                try: 
                    return 'port', str(int(p2_clean))
                except ValueError: return None, None
                
        p2_clean = p2.lower()
        if p2_clean.startswith('+.'): p2_clean = p2_clean[2:]
        elif p2_clean.startswith('*.'): p2_clean = p2_clean[2:]
        elif p2_clean.startswith('.'): p2_clean = p2_clean[1:]
        elif p2_clean.startswith('+'): p2_clean = p2_clean[1:]
        p2_clean = p2_clean.lstrip('.')

        if internal_type == 'suffix': 
            if has_invalid_domain_chars(p2_clean): return None, None
            if '.' not in p2_clean: p2_clean = '.' + p2_clean
            encoded_d = try_punycode_encode(p2_clean)
            if encoded_d:
                return 'suffix', (encoded_d if encoded_d.startswith('.') else '.' + encoded_d)
            return None, None
            
        if internal_type == 'full': 
            if '*' in p2_clean or '?' in p2_clean: return 'wildcard', p2.lower()
            if IPV4_REGEX.match(p2_clean): 
                return ('ip', p2_clean) if validate_ip_mask(p2_clean, False) else (None, None)
            if IPV6_REGEX.match(p2_clean) or IPV6_REGEX.match(p2_clean.split('/')[0]): 
                return ('ip6', p2_clean) if validate_ip_mask(p2_clean, True) else (None, None)
            if has_invalid_domain_chars(p2_clean): return None, None
            encoded_d = try_punycode_encode(p2_clean)
            return ('full', encoded_d) if (encoded_d and DOMAIN_PATTERN.match(encoded_d)) else (None, None)
            
        if internal_type == 'keyword': return 'keyword', p2_clean
            
        if internal_type in ['ip', 'ip6']:
            raw_ip = p2_clean.split(',')[0].strip()  
            if ':' in raw_ip and '[' not in raw_ip and raw_ip.count(':') == 1:
                raw_ip = raw_ip.split(':')[0] 
            if IPV6_REGEX.match(raw_ip) or IPV6_REGEX.match(raw_ip.split('/')[0]):
                return ('ip6', raw_ip) if validate_ip_mask(raw_ip, True) else (None, None)
            if IPV4_REGEX.match(raw_ip) or IPV4_REGEX.match(raw_ip.split('/')[0]):
                return ('ip', raw_ip) if validate_ip_mask(raw_ip, False) else (None, None)
            return None, None
            
        if internal_type == 'process': return 'process', p2.lower()
        return None, None

    raw_val = line.lower().split('#')[0].split('//')[0].strip()
    if not raw_val or any(c in raw_val for c in ['*', '?', '(', ')', '|', '^', '$', '\\']):
        return None, None

    raw_val = raw_val.rstrip('.')
    if not raw_val: return None, None

    if '/' in raw_val and not (IPV4_REGEX.match(raw_val) or IPV6_REGEX.match(raw_val) or IPV6_REGEX.match(raw_val.split('/')[0])):
        return None, None

    if ':' in raw_val:
        if raw_val.count(':') == 1:
            possible_ip_or_domain, port = raw_val.split(':')
            if port.isdigit() and possible_ip_or_domain: raw_val = possible_ip_or_domain
            else: return None, None
        else:
            clean_ipv6 = raw_val.strip('[]')
            if not IPV6_REGEX.match(clean_ipv6): return None, None
            raw_val = clean_ipv6

    if IPV4_REGEX.match(raw_val):
        return ('ip', raw_val) if validate_ip_mask(raw_val, False) else (None, None)
    if IPV6_REGEX.match(raw_val):
        return ('ip6', raw_val) if validate_ip_mask(raw_val, True) else (None, None)
        
    if has_invalid_domain_chars(raw_val): return None, None

    is_explicit_suffix = False
    if raw_val.startswith('+.'):   raw_val = raw_val[2:]; is_explicit_suffix = True
    elif raw_val.startswith('.'):  raw_val = raw_val[1:]; is_explicit_suffix = True
    elif raw_val.startswith('+'):  raw_val = raw_val[1:]; is_explicit_suffix = True
        
    raw_val = raw_val.lstrip('.')
    if not raw_val: return None, None
        
    raw_val = try_punycode_encode(raw_val)
    if not raw_val or not DOMAIN_PATTERN.match(raw_val): return None, None

    if is_explicit_suffix:
        return 'suffix', raw_val
    else:
        if 'PUBLIC_SUFFIX_BLACKLIST' in globals():
            if raw_val in PUBLIC_SUFFIX_BLACKLIST: return None, None
            parts = raw_val.split('.')
            parts_count = len(parts)
            last_2_parts = '.'.join(parts[-2:]) if parts_count >= 2 else ''
            is_compound_public = last_2_parts in PUBLIC_SUFFIX_BLACKLIST

            if parts_count == 2: return 'suffix', raw_val
            elif parts_count == 3: return ('suffix', raw_val) if is_compound_public else ('full', raw_val)
            else: return 'full', raw_val
                
        return ('suffix', raw_val) if raw_val.count('.') == 1 else ('full', raw_val)

def optimize_domains(rules: dict):
    if 'suffix' not in rules or 'full' not in rules: return
    safe_suffixes = {s if s.startswith('.') else '.' + s for s in rules['suffix'] if s}
    sorted_suffixes = sorted(list(safe_suffixes), key=len)
    optimized_suffixes = set()
    
    for suf in sorted_suffixes:
        is_sub = False
        for opt in optimized_suffixes:
            if suf == opt or suf.endswith(opt):
                is_sub = True
                break
        if not is_sub: optimized_suffixes.add(suf)
            
    rules['suffix'] = {s.lstrip('.') for s in optimized_suffixes}
    optimized_fulls = set()
    for f_dom in rules['full']:
        is_covered = False
        for suf in rules['suffix']:
            if f_dom == suf or f_dom.endswith('.' + suf):
                is_covered = True
                break
        if not is_covered: optimized_fulls.add(f_dom)
    rules['full'] = optimized_fulls

# ==========================================
# 5. 网络 I/O 与规则聚合分发流
# ==========================================
def fetch_single_url(remote_url):
    try:
        req = urllib.request.Request(
            remote_url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return remote_url, content.splitlines()
    except Exception as e:
        print(f"Warning: Failed to fetch {remote_url} - {e}")
        return remote_url, []

def fetch_and_merge_rules(base_name, policy):
    rules = {k: set() for k in ['remove', 'process', 'port', 'full', 'suffix', 'keyword', 'ip', 'ip6', 'useragent', 'wildcard', 'regex']}  
    source_enable, _ = parse_target_config(policy, 'source', base_name)
    source_file_name = base_name.lower()
    source_path = os.path.join(SOURCE_DIR, f"{source_file_name}.txt")

    if os.path.exists(source_path):
        with open(source_path, 'r', encoding='utf-8') as f_local:
            for line in f_local:
                r_type, payload = clean_and_parse_line(line)
                if payload and r_type in rules: rules[r_type].add(payload)

    remote_url_cfg = policy.get('url', [])
    url_list = remote_url_cfg if isinstance(remote_url_cfg, list) else ([remote_url_cfg] if remote_url_cfg else [])

    if url_list:
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(fetch_single_url, url): url for url in url_list}
            for future in as_completed(future_to_url):
                url, lines = future.result()
                for line in lines:
                    r_type, payload = clean_and_parse_line(line)
                    if payload and r_type in rules: rules[r_type].add(payload)

    if rules['remove']:
        remove_set = rules['remove']
        for r_type in rules:
            if r_type != 'remove': rules[r_type] -= remove_set
                
    optimize_domains(rules) 

    if source_enable and any(len(rules[k]) > 0 for k in rules):
        if rules.get('port'):
            cleaned_ports = set()
            for v in rules['port']:
                if isinstance(v, (tuple, list)):
                    cleaned_ports.add(f"{v[0]}-{v[1]}" if v[0] != v[1] else str(v[0]))
                else:
                    cleaned_ports.add(str(v).replace(':', '-').strip())
            rules['port'] = cleaned_ports

        with open(source_path, 'w', encoding='utf-8') as f_source:
            f_source.write(f"# === {source_file_name} Combined Base Rules ===\n\n")
            for r_type in ['remove', 'process', 'port', 'full', 'suffix', 'keyword', 'ip', 'ip6', 'useragent', 'wildcard', 'regex']:
                if rules[r_type]:
                    f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                    for val in sorted(rules[r_type]):
                        if r_type == 'ip': 
                            f_source.write(f"{r_type},{ensure_ip_mask(val)}\n")
                        elif r_type == 'ip6': 
                            f_source.write(f"{r_type},{ensure_ip_mask(val, True)}\n")
                        else: 
                            f_source.write(f"{r_type},{val}\n")
                    f_source.write("\n")
    return rules

def dispatch_rules_to_targets(base_name, policy, rules, global_matrix):
    qx_en, qx_name = parse_target_config(policy, 'qx', base_name)
    sr_en, sr_name = parse_target_config(policy, 'sr', base_name)
    mhm_en, mhm_name = parse_target_config(policy, 'mihomo', base_name)
    sb_en, sb_name = parse_target_config(policy, 'singbox', base_name)
    
    qx_policy_label = policy.get('qx_policy', base_name.capitalize() if base_name.lower() not in ['direct', 'reject'] else base_name.lower())

    if qx_en:
        if qx_name not in global_matrix['qx']:
            global_matrix['qx'][qx_name] = {'policy_label': qx_policy_label, 'full': set(), 'suffix': set(), 'keyword': set(), 'ip': set(), 'ip6': set(), 'useragent': set(), 'wildcard': set(), 'regex': set()}
        for k in global_matrix['qx'][qx_name].keys():
            if k != 'policy_label': global_matrix['qx'][qx_name][k].update(rules[k])

    if sr_en:
        if sr_name not in global_matrix['sr']: global_matrix['sr'][sr_name] = {k: set() for k in rules.keys()}
        for k in rules.keys(): global_matrix['sr'][sr_name][k].update(rules[k])

    if mhm_en:
        if mhm_name not in global_matrix['mihomo']: global_matrix['mihomo'][mhm_name] = {k: set() for k in rules.keys()}
        for k in rules.keys(): global_matrix['mihomo'][mhm_name][k].update(rules[k])

    if sb_en:
        if sb_name not in global_matrix['singbox']: global_matrix['singbox'][sb_name] = {k: set() for k in rules.keys()}
        for k in rules.keys(): global_matrix['singbox'][sb_name][k].update(rules[k])

    pac_val = policy.get('pac')
    if pac_val is not False and str(pac_val).lower() != 'false': 
        pac_en = False
        pac_name = base_name
        if pac_val and pac_val is not True and str(pac_val).lower() != 'true':
            pac_en, pac_name = True, str(pac_val).strip()
        elif pac_val is True or str(pac_val).lower() == 'true' or base_name.lower() in ['direct', 'china']:
            pac_en = True
            
        if pac_en:
            if pac_name not in global_matrix['pac']: global_matrix['pac'][pac_name] = set()
            global_matrix['pac'][pac_name].update(rules['suffix'])
            global_matrix['pac'][pac_name].update(rules['full'])

# ==========================================
# 6. 【新提炼】独立专职 I/O 模块
# ==========================================
def normalize_and_discover_local_sources(router_cleaned):
    """
    【从 main 解耦】专门负责本地 txt 文件的文件名大小写平滑归一化与路由底座初始化。
    """
    if not os.path.exists(SOURCE_DIR): return
    for f in os.listdir(SOURCE_DIR):
        if f.endswith('.txt'):
            if not f.islower():
                old_path = os.path.join(SOURCE_DIR, f)
                new_f = f.lower()
                new_path = os.path.join(SOURCE_DIR, new_f)
                if os.path.exists(new_path):
                    try:
                        with open(old_path, 'r', encoding='utf-8') as f_old:
                            old_content = f_old.read()
                        with open(new_path, 'a', encoding='utf-8') as f_new:
                            f_new.write("\n" + old_content)
                        os.remove(old_path)
                    except Exception: pass
                else:
                    try: os.rename(old_path, new_path)
                    except Exception: pass
                f = new_f

            local_base_name = os.path.splitext(f)[0]
            if local_base_name in router_cleaned: continue
            router_cleaned[local_base_name] = {'name': local_base_name, 'url': []}

def generate_mrs_srs_temp_files(base_name, policy, rules):

    if 'classic' in base_name.lower() or 'nodomain' in base_name.lower(): return

    mrs_en, mrs_name = parse_target_config(policy, 'mrs', base_name)
    srs_en, srs_name = parse_target_config(policy, 'srs', base_name)
    if not mrs_en and not srs_en: return

    has_ipcidr_cfg = is_truthy_cfg(policy, 'ipcidr')
    has_domain_cfg = is_truthy_cfg(policy, 'domain')

    # Mihomo 临时 Payload 生成
    if mrs_en:
        target_ip_name = mrs_name if is_ip_centric_name(mrs_name) else (f"{mrs_name}_ip" if has_ipcidr_cfg else None)
        target_domain_name = f"{mrs_name}_domain" if is_ip_centric_name(mrs_name) and has_domain_cfg else (mrs_name if not is_ip_centric_name(mrs_name) else None)

        if target_ip_name:
            combined_ips = extract_combined_cidrs(rules)
            if combined_ips:
                with open(os.path.join(MIHOMO_DIR, f"tmp_ip_{target_ip_name}.yaml"), 'w', encoding='utf-8') as f:
                    f.write("payload:\n")
                    for item in combined_ips: f.write(f"  - '{item}'\n")

        if target_domain_name:
            if rules.get('suffix') or rules.get('full') or rules.get('keyword') or rules.get('wildcard') or rules.get('regex'):
                with open(os.path.join(MIHOMO_DIR, f"tmp_domain_{target_domain_name}.yaml"), 'w', encoding='utf-8') as f:
                    f.write("payload:\n")
                    for item in sorted(rules.get('full', [])): f.write(f"  - DOMAIN,{item}\n")
                    for item in sorted(rules.get('suffix', [])): f.write(f"  - DOMAIN-SUFFIX,{item}\n")
                    for item in sorted(rules.get('keyword', [])): f.write(f"  - DOMAIN-KEYWORD,{item}\n")
                    for val in sorted(rules.get('wildcard', [])): f.write(f"  - DOMAIN-WILDCARD,{val}\n")
                    for item in sorted(rules.get('regex', [])): f.write(f"  - DOMAIN-REGEX,{item}\n")

    # Singbox 临时 JSON 生成
    if srs_en:
        target_ip_name = srs_name if is_ip_centric_name(srs_name) else (f"{srs_name}_ip" if has_ipcidr_cfg else None)
        target_domain_name = f"{srs_name}_domain" if is_ip_centric_name(srs_name) and has_domain_cfg else (srs_name if not is_ip_centric_name(srs_name) else None)

        if target_ip_name:
            combined_ips = extract_combined_cidrs(rules)
            if combined_ips:
                sb_tmp_ip = {"version": 2, "rules": [{"ip_cidr": combined_ips}]}
                with open(os.path.join(SINGBOX_DIR, f"tmp_ip_{target_ip_name}.json"), 'w', encoding='utf-8') as f:
                    json.dump(sb_tmp_ip, f, indent=2, ensure_ascii=False)
                    
        if target_domain_name:
            sb_tmp_domain = {"version": 2, "rules": []}
            if rules.get('full'): sb_tmp_domain["rules"].append({"domain": sorted(list(rules['full']))})      
            if rules.get('suffix'): sb_tmp_domain["rules"].append({"domain_suffix": sorted(list(rules['suffix']))})      
            if rules.get('keyword'): sb_tmp_domain["rules"].append({"domain_keyword": sorted(list(rules['keyword']))})
            if rules.get('port'): 
                p_list, p_range = parse_ports_for_singbox(rules['port'])
                if p_list: sb_tmp_domain["rules"].append({"port": p_list})
                if p_range: sb_tmp_domain["rules"].append({"port_range": p_range})
            if rules.get('wildcard') or rules.get('regex'):
                regex_list = [convert_wildcard_to_regex(w) for w in rules.get('wildcard', [])] + list(rules.get('regex', []))
                sb_tmp_domain["rules"].append({"domain_regex": sorted(list(set(regex_list)))})
                
            if sb_tmp_domain["rules"]:
                with open(os.path.join(SINGBOX_DIR, f"tmp_domain_{target_domain_name}.json"), 'w', encoding='utf-8') as f:
                    json.dump(sb_tmp_domain, f, indent=2, ensure_ascii=False)

# ==========================================
# 7. 主程序流调度核心
# ==========================================
def main():
    router_cleaned = {}
    allocated_names = set()
    
    for policy_card in FILE_POLICY_ROUTER:
        raw_name = policy_card.get('name', '')
        real_name = get_smart_base_name(raw_name, policy_card, allocated_names)
        allocated_names.add(real_name)
        router_cleaned[real_name] = policy_card

    normalize_and_discover_local_sources(router_cleaned)

    global_matrix = {
        'qx': {}, 'sr': {}, 'mihomo': {}, 'singbox': {}, 'pac': {}
    }

    # 步骤 3：多渠道融合分发大循环
    for target_base_name, policy_card in router_cleaned.items():
        rules_in_memory = fetch_and_merge_rules(target_base_name, policy_card)       
        
        # 3.1 内存矩阵上色（安全纯净无 I/O）
        dispatch_rules_to_targets(target_base_name, policy_card, rules_in_memory, global_matrix)
        
        # 3.2 【解耦调用】专职生成临时过渡配置
        generate_mrs_srs_temp_files(target_base_name, policy_card, rules_in_memory)
  
    # [QuantumultX]
    for g_name, g_rules in global_matrix['qx'].items():
        qx_path = os.path.join(QUANTUMULTX_DIR, f"{g_name}.list")
        qx_policy = g_rules['policy_label']
        optimize_domains(g_rules)
        with open(qx_path, 'w', encoding='utf-8') as f:
            f.write(f"# Quantumult X Aggregated Rule-Set: {g_name}\n\n")
            
            qx_ordered_types = [
                ('host', 'full'), ('host-suffix', 'suffix'), ('host-keyword', 'keyword'),
                ('ip-cidr', 'ip'), ('ip6-cidr', 'ip6')
            ]
            for qx_prefix, ik in qx_ordered_types:
                for val in sorted(g_rules.get(ik, [])):
                    if 'ip' in ik: f.write(f"{qx_prefix}, {ensure_ip_mask(val, ik=='ip6')}, {qx_policy}, no-resolve\n")
                    else: f.write(f"{qx_prefix}, {val}, {qx_policy}\n")

            for val in sorted(g_rules.get('useragent', [])):
                qx_ua = f"*{val}*" if not ('*' in val or '?' in val) else val
                if ',' in qx_ua: qx_ua = f'"{qx_ua}"'
                f.write(f"user-agent, {qx_ua}, {qx_policy}\n")
        
            for val in sorted(g_rules.get('wildcard', [])): f.write(f"host-wildcard, {val}, {qx_policy}\n")
            for val in sorted(g_rules.get('regex', [])): f.write(f"host-regex, {val.strip()}, {qx_policy}\n")

    # [Shadowrocket]
    for g_name, g_rules in global_matrix['sr'].items():
        sr_path = os.path.join(SHADOWROCKET_DIR, f"{g_name}.list")
        optimize_domains(g_rules)
        with open(sr_path, 'w', encoding='utf-8') as f:
            f.write(f"# Shadowrocket Rule-Set: {g_name}\n\n")
            for val in sorted(list({str(p) for p in g_rules.get('port', [])})):
                if '-' in val or ':' in val: continue
                f.write(f"DST-PORT,{val}\n")

            sr_ordered_types = [
                ('DOMAIN', 'full'), ('DOMAIN-SUFFIX', 'suffix'), ('DOMAIN-KEYWORD', 'keyword'),
                ('IP-CIDR', 'ip'), ('IP-CIDR6', 'ip6'), ('USER-AGENT', 'useragent'),
                ('DOMAIN-WILDCARD', 'wildcard'), ('DOMAIN-REGEX', 'regex')
            ]
            for raw_type, ik in sr_ordered_types:
                for val in sorted(g_rules.get(ik, [])):
                    if ik in ['ip', 'ip6']: f.write(f"{raw_type},{ensure_ip_mask(val, ik=='ip6')},no-resolve\n")
                    else: f.write(f"{raw_type},{val}\n")

    # [Mihomo]
    for g_name, g_rules in global_matrix['mihomo'].items():
        mihomo_path = os.path.join(MIHOMO_DIR, f"{g_name}.yaml")
        optimize_domains(g_rules)
        with open(mihomo_path, 'w', encoding='utf-8') as f:
            f.write(f"# Mihomo Payload Rule-Set: {g_name}\npayload:\n")
            ordered_types = [
                ('PROCESS-NAME', 'process'), ('DST-PORT', 'port'), ('DOMAIN', 'full'),
                ('DOMAIN-SUFFIX', 'suffix'), ('DOMAIN-KEYWORD', 'keyword'),
                ('IP-CIDR', 'ip'), ('IP-CIDR6', 'ip6'), ('DOMAIN-WILDCARD', 'wildcard'), ('DOMAIN-REGEX', 'regex')
            ]
            for raw_type, ik in ordered_types:
                for val in sorted(g_rules.get(ik, [])):
                    if ik in ['ip', 'ip6']: f.write(f"  - {raw_type},{ensure_ip_mask(val, ik=='ip6')},no-resolve\n")
                    else: f.write(f"  - {raw_type},{val}\n")
    
    # [Singbox]
    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path = os.path.join(SINGBOX_DIR, f"{g_name}.json")
        g_rules = {k: list(v) if isinstance(v, (list, set, tuple)) else v for k, v in raw_rules.items()}
        optimize_domains(g_rules)

        sb_data = {"version": 2, "rules": []}
        net_block = {}
        sb_domain_mapping = [('full', 'domain'), ('suffix', 'domain_suffix'), ('keyword', 'domain_keyword')]

        for ik, sb_key in sb_domain_mapping:
            if g_rules.get(ik): net_block[sb_key] = sorted(list(g_rules[ik]))
            
        combined_ips = extract_combined_cidrs(g_rules)
        if combined_ips: net_block["ip_cidr"] = combined_ips
            
        if g_rules.get('wildcard') or g_rules.get('regex'):
            regex_list = [convert_wildcard_to_regex(w) for w in g_rules.get('wildcard', [])] + g_rules.get('regex', [])
            net_block["domain_regex"] = sorted(list(set(regex_list)))
            
        if net_block: sb_data["rules"].append(net_block)
        if g_rules.get('process'): sb_data["rules"].append({"process_name": sorted(list(g_rules['process']))})
            
        if g_rules.get('port'): 
            p_list, p_range = parse_ports_for_singbox(g_rules['port'])
            port_block = {}
            if p_list: port_block["port"] = p_list
            if p_range: port_block["port_range"] = p_range
            if port_block: sb_data["rules"].append(port_block)

        if g_rules.get('logical_and'):
            for and_rule in g_rules['logical_and']: sb_data["rules"].append(and_rule)
                
        with open(sb_path, 'w', encoding='utf-8') as f:
            json.dump(sb_data, f, indent=2, ensure_ascii=False)

    # [PAC 生产流]
    for g_name, raw_domains in global_matrix['pac'].items():
        pac_path = os.path.join(PAC_DIR, f"{g_name}.pac")
        combined_domains = set(raw_domains.get('full', [])) | set(raw_domains.get('suffix', [])) if isinstance(raw_domains, dict) else (set(raw_domains) if raw_domains else set())
        direct_domains = sorted(list(combined_domains))
        
        with open(pac_path, 'w', encoding='utf-8') as f:
            f.write("var IP_ADDRESS = '127.0.0.1:7891';\nvar PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; DIRECT';\n\nvar DIRECT_DOMAINS = {\n")
            for i, domain in enumerate(direct_domains):
                f.write(f'    "{domain}": 1{"," if i < len(direct_domains) - 1 else ""}\n')
            f.write("};\n\nfunction FindProxyForURL(url, host) {\n    if (isPlainHostName(host) || /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {\n        return \"DIRECT\";\n    }\n\n    var suffix = host.toLowerCase();\n    while (suffix) {\n        if (DIRECT_DOMAINS.hasOwnProperty(suffix)) {\n            return \"DIRECT\";\n        }\n        var pos = suffix.indexOf(\'.\');\n        if (pos === -1) break;\n        suffix = suffix.substring(pos + 1);\n    }\n\n    return PROXY_METHOD;\n}\n")

if __name__ == '__main__':
    main()
