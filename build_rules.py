# -*- coding: utf-8 -*-
import os
import json
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

RULESET_BASE_DIR = 'ruleset'
SOURCE_DIR = os.path.join(RULESET_BASE_DIR, 'source')
SHADOWROCKET_DIR = os.path.join(RULESET_BASE_DIR, 'shadowrocket')
QUANTUMULTX_DIR = os.path.join(RULESET_BASE_DIR, 'quantumultx')
MIHOMO_DIR = os.path.join(RULESET_BASE_DIR, 'mihomo')
PAC_DIR = os.path.join(RULESET_BASE_DIR, 'pac')
SINGBOX_DIR = os.path.join(RULESET_BASE_DIR, 'singbox')

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

def clean_and_parse_line(line):
    line = line.strip()
    if not line or line.startswith(('#', '//', ';')) or line == 'payload:':
        return None, None
    if line.startswith('-'):
        line = line.lstrip('-').strip()
    line = line.strip("'").strip('"').strip()
    
    if not line:
        return None, None

    if ',' in line:
        possible_tag = line.split(',')[0].strip().upper()
        known_tags = [
            'DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX', 'DOMAIN', 'HOST', 'FULL',
            'DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD', 'DOMAIN-REGEX', 'REGEX',
            'DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD', 'IP-CIDR', 'IP',
            'IP-CIDR6', 'IP6-CIDR', 'IP6', 'PROCESS-NAME', 'PROCESS', 
            'USER-AGENT', 'USERAGENT', 'DST-PORT', 'DEST-PORT', 'PORT', 'REMOVE'
        ]
        
        if possible_tag in known_tags:
            p1, p2 = [x.strip() for x in line.split(',', 1)]
            
            if p1 in ['AND', 'OR', 'NOT']:
                return None, None
                
            if p1 == 'REMOVE':
                rem_parts = [x.strip() for x in p2.split(',')]
                target_val = rem_parts[1].lower() if len(rem_parts) >= 2 else rem_parts[0].lower()
                return 'remove', target_val.lstrip('+.*')

            if p1 not in ['DOMAIN-REGEX', 'REGEX', 'USER-AGENT', 'USERAGENT']:
                p2 = p2.split('#')[0].split('//')[0].strip()

            if p1 in ['DOMAIN-REGEX', 'REGEX']:
                prophecies = ['(?=', '(?<=', '(?!', '(?<!']
                if any(lookaround in p2 for lookaround in prophecies) or '/' in p2 or '?' in p2:
                    return None, None
                try:
                    p2_low = p2.lower()
                    re.compile(p2_low)
                    return 'regex', p2_low
                except re.error:
                    return None, None

            if p1 in ['DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD']:
                return 'wildcard', p2.lower()

            if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX', 'DOMAIN', 'HOST', 'FULL']:
                if '/' in p2 or '?' in p2:
                    return None, None

            p2_clean = p2.lower()
            if p2_clean.startswith('+.'): p2_clean = p2_clean[2:]
            elif p2_clean.startswith('*.'): p2_clean = p2_clean[2:]
            elif p2_clean.startswith('.'): p2_clean = p2_clean[1:]
            elif p2_clean.startswith('+'): p2_clean = p2_clean[1:]
            p2_clean = p2_clean.lstrip('.')

            if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']: 
                if has_invalid_domain_chars(p2_clean): return None, None
                encoded_d = try_punycode_encode(p2_clean)
                return ('suffix', encoded_d) if (encoded_d and DOMAIN_PATTERN.match(encoded_d)) else (None, None)
                
            if p1 in ['DOMAIN', 'HOST', 'FULL']: 
                if '*' in p2_clean or '?' in p2_clean: 
                    return 'wildcard', p2.lower()
                if IPV4_REGEX.match(p2_clean): 
                    return ('ip', p2_clean) if validate_ip_mask(p2_clean, False) else (None, None)
                if IPV6_REGEX.match(p2_clean) or IPV6_REGEX.match(p2_clean.split('/')[0]): 
                    return ('ip6', p2_clean) if validate_ip_mask(p2_clean, True) else (None, None)
                if has_invalid_domain_chars(p2_clean): return None, None
                encoded_d = try_punycode_encode(p2_clean)
                return ('full', encoded_d) if (encoded_d and DOMAIN_PATTERN.match(encoded_d)) else (None, None)
                
            if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']: 
                return 'keyword', p2_clean
                
            if p1 in ['IP-CIDR', 'IP', 'IP-CIDR6', 'IP6-CIDR', 'IP6']:
                raw_ip = p2_clean.split(',')[0].strip()  
                if ':' in raw_ip and '[' not in raw_ip and raw_ip.count(':') == 1:
                    raw_ip = raw_ip.split(':')[0] 
                if IPV6_REGEX.match(raw_ip) or IPV6_REGEX.match(raw_ip.split('/')[0]):
                    return ('ip6', raw_ip) if validate_ip_mask(raw_ip, True) else (None, None)
                if IPV4_REGEX.match(raw_ip) or IPV4_REGEX.match(raw_ip.split('/')[0]):
                    return ('ip', raw_ip) if validate_ip_mask(raw_ip, False) else (None, None)
                return None, None
                
            if p1 in ['PROCESS-NAME', 'PROCESS']: return 'process', p2.lower()
            if p1 in ['USER-AGENT', 'USERAGENT']: return 'useragent', p2.lower()
            if p1 in ['DST-PORT', 'DEST-PORT', 'PORT']: return 'port', p2.lower()      
            
            return None, None

    raw_val = line.lower()
    
    raw_val = raw_val.split('#')[0].split('//')[0].strip()
    if not raw_val:
        return None, None

    if any(c in raw_val for c in ['*', '?', '(', ')', '|', '^', '$', '\\']):
        return None, None

    raw_val = raw_val.rstrip('.')
    if not raw_val:
        return None, None

    if '/' in raw_val:
        if not (IPV4_REGEX.match(raw_val) or IPV6_REGEX.match(raw_val) or IPV6_REGEX.match(raw_val.split('/')[0])):
            return None, None

    if ':' in raw_val:
        if raw_val.count(':') == 1:
            possible_ip_or_domain, port = raw_val.split(':')
            if port.isdigit() and possible_ip_or_domain:
                raw_val = possible_ip_or_domain
            else:
                return None, None
        else:
            clean_ipv6 = raw_val.strip('[]')
            if not IPV6_REGEX.match(clean_ipv6):
                return None, None
            raw_val = clean_ipv6

    if IPV4_REGEX.match(raw_val):
        return ('ip', raw_val) if validate_ip_mask(raw_val, False) else (None, None)
    if IPV6_REGEX.match(raw_val):
        return ('ip6', raw_val) if validate_ip_mask(raw_val, True) else (None, None)
        
    if has_invalid_domain_chars(raw_val):
        return None, None

    is_explicit_suffix = False
    if raw_val.startswith('+.'):   raw_val = raw_val[2:]; is_explicit_suffix = True
    elif raw_val.startswith('.'):  raw_val = raw_val[1:]; is_explicit_suffix = True
    elif raw_val.startswith('+'):  raw_val = raw_val[1:]; is_explicit_suffix = True
        
    raw_val = raw_val.lstrip('.')
    if not raw_val:
        return None, None
        
    raw_val = try_punycode_encode(raw_val)
    if not raw_val or not DOMAIN_PATTERN.match(raw_val):
        return None, None

    if is_explicit_suffix:
        return 'suffix', raw_val
    else:
        if 'PUBLIC_SUFFIX_BLACKLIST' in globals() or 'PUBLIC_SUFFIX_BLACKLIST' in locals():
            if raw_val in PUBLIC_SUFFIX_BLACKLIST:
                return None, None
            
            parts = raw_val.split('.')
            parts_count = len(parts)
            last_2_parts = '.'.join(parts[-2:]) if parts_count >= 2 else ''
            is_compound_public = last_2_parts in PUBLIC_SUFFIX_BLACKLIST

            if parts_count == 2:
                return 'suffix', raw_val
            elif parts_count == 3:
                return ('suffix', raw_val) if is_compound_public else ('full', raw_val)
            else:
                return 'full', raw_val
                
        return ('suffix', raw_val) if raw_val.count('.') == 1 else ('full', raw_val)

def optimize_domains(rules):
    if rules.get('suffix'):
        reversed_domains = sorted(['.'.join(reversed(d.split('.'))) + '.' for d in rules['suffix']])
        clean_reversed = []
        for rd in reversed_domains:
            if not clean_reversed or not rd.startswith(clean_reversed[-1]):
                clean_reversed.append(rd)
        rules['suffix'] = {'.'.join(reversed(rd.rstrip('.').split('.'))) for rd in clean_reversed}

    if rules.get('full'):
        rules['full'] = set(rules['full'])

def ensure_ip_mask(ip_str, is_ipv6=False):
    if '/' in ip_str: return ip_str
    return f"{ip_str}/128" if is_ipv6 else f"{ip_str}/32"

def parse_ports_for_singbox(port_set):
    p_list, p_range = [], []
    for p in port_set:
        if '-' in p: p_range.append(p.replace('-', ':'))
        elif ':' in p: p_range.append(p)
        else: p_list.append(int(p))
    return sorted(p_list), sorted(p_range)

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
                if payload and r_type in rules:
                    rules[r_type].add(payload)

    remote_url_cfg = policy.get('url', [])
    url_list = remote_url_cfg if isinstance(remote_url_cfg, list) else ([remote_url_cfg] if remote_url_cfg else [])

    if url_list:
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(fetch_single_url, url): url for url in url_list}
            for future in as_completed(future_to_url):
                url, lines = future.result()
                for line in lines:
                    r_type, payload = clean_and_parse_line(line)
                    if payload and r_type in rules:
                        rules[r_type].add(payload)

    if rules['remove']:
        remove_set = rules['remove']
        for r_type in rules:
            if r_type != 'remove':
                rules[r_type] -= remove_set
                
    optimize_domains(rules) 

    if source_enable:
        has_any_rule = any(len(rules[k]) > 0 for k in rules)
        if has_any_rule:
            with open(source_path, 'w', encoding='utf-8') as f_source:
                f_source.write(f"# === {source_file_name} Combined Base Rules ===\n\n")
                for r_type in ['remove', 'process', 'port', 'full', 'suffix', 'keyword', 'ip', 'ip6', 'useragent', 'wildcard', 'regex']:
                    if rules[r_type]:
                        f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                        for val in sorted(rules[r_type]):
                            if r_type == 'ip': f_source.write(f"{r_type},{ensure_ip_mask(val)}\n")
                            elif r_type == 'ip6': f_source.write(f"{r_type},{ensure_ip_mask(val, True)}\n")
                            else: f_source.write(f"{r_type},{val}\n")
                        f_source.write("\n")

    return rules

def dispatch_rules_to_targets(base_name, policy, rules, global_matrix):
	
    qx_en, qx_name = parse_target_config(policy, 'qx', base_name)
    sr_en, sr_name = parse_target_config(policy, 'sr', base_name)
    mhm_en, mhm_name = parse_target_config(policy, 'mihomo', base_name)
    sb_en, sb_name = parse_target_config(policy, 'singbox', base_name)
    mrs_en, mrs_name = parse_target_config(policy, 'mrs', base_name)
    srs_en, srs_name = parse_target_config(policy, 'srs', base_name)
    
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

    if 'classic' in base_name.lower() or 'nodomain' in base_name.lower():
        return

    if not mrs_en and not srs_en:
        return

    has_ipcidr_cfg = is_truthy_cfg(policy, 'ipcidr')
    has_domain_cfg = is_truthy_cfg(policy, 'domain')

    if mrs_en:
        target_ip_name = None
        target_domain_name = None
        
        name_has_ip = is_ip_centric_name(mrs_name)
        
        if name_has_ip:
            target_ip_name = mrs_name
            target_domain_name = f"{mrs_name}_domain" if has_domain_cfg else None
        else:
            target_domain_name = mrs_name
            target_ip_name = f"{mrs_name}_ip" if has_ipcidr_cfg else None

        if target_ip_name:
            combined_ips = sorted(list(set([ensure_ip_mask(i) for i in rules['ip']] + [ensure_ip_mask(i, True) for i in rules['ip6']])))
            if combined_ips:
                with open(os.path.join(MIHOMO_DIR, f"tmp_ip_{target_ip_name}.yaml"), 'w', encoding='utf-8') as f:
                    f.write("payload:\n")
                    for item in combined_ips: f.write(f"  - '{item}'\n")

        if target_domain_name:
            if rules['suffix'] or rules['full'] or rules['keyword'] or rules['wildcard'] or rules['regex']:
                with open(os.path.join(MIHOMO_DIR, f"tmp_domain_{target_domain_name}.yaml"), 'w', encoding='utf-8') as f:
                    f.write("payload:\n")
                    for item in sorted(rules['full']): f.write(f"  - DOMAIN,{item}\n")
                    for item in sorted(rules['suffix']): f.write(f"  - DOMAIN-SUFFIX,{item}\n")
                    for item in sorted(rules['keyword']): f.write(f"  - DOMAIN-KEYWORD,{item}\n")
                    for val in sorted(rules['wildcard']): f.write(f"  - DOMAIN-WILDCARD,{val}\n")
                    for item in sorted(rules['regex']): f.write(f"  - DOMAIN-REGEX,{item}\n")

    if srs_en:
        target_ip_name = None
        target_domain_name = None

        name_has_ip = is_ip_centric_name(srs_name)
        
        if name_has_ip:
            target_ip_name = srs_name
            target_domain_name = f"{srs_name}_domain" if has_domain_cfg else None
        else:
            target_domain_name = srs_name
            target_ip_name = f"{srs_name}_ip" if has_ipcidr_cfg else None

        if target_ip_name:
            combined_ips = sorted(list(set([ensure_ip_mask(i) for i in rules['ip']] + [ensure_ip_mask(i, True) for i in rules['ip6']])))
            if combined_ips:
                sb_tmp_ip = {"version": 2, "rules": [{"ip_cidr": combined_ips}]}
                with open(os.path.join(SINGBOX_DIR, f"tmp_ip_{target_ip_name}.json"), 'w', encoding='utf-8') as f:
                    json.dump(sb_tmp_ip, f, indent=2, ensure_ascii=False)
                    
        if target_domain_name:
            sb_tmp_domain = {"version": 2, "rules": []}
            if rules['full']: sb_tmp_domain["rules"].append({"domain": sorted(list(rules['full']))})      
            if rules['suffix']: sb_tmp_domain["rules"].append({"domain_suffix": sorted(list(rules['suffix']))})      
            if rules['keyword']: sb_tmp_domain["rules"].append({"domain_keyword": sorted(list(rules['keyword']))})
            if rules['port']: 
                p_list, p_range = parse_ports_for_singbox(rules['port'])
                if p_list: sb_tmp_domain["rules"].append({"port": p_list})
                if p_range: sb_tmp_domain["rules"].append({"port_range": p_range})
            if rules['wildcard'] or rules['regex']:
                regex_list = [convert_wildcard_to_regex(w) for w in rules['wildcard']]
                for regex_val in rules['regex']: regex_list.append(regex_val)
                sb_tmp_domain["rules"].append({"domain_regex": sorted(list(set(regex_list)))})
                
            if sb_tmp_domain["rules"]:
                with open(os.path.join(SINGBOX_DIR, f"tmp_domain_{target_domain_name}.json"), 'w', encoding='utf-8') as f:
                    json.dump(sb_tmp_domain, f, indent=2, ensure_ascii=False)

def convert_wildcard_to_regex(wildcard_str):
    if '*' not in wildcard_str and '?' not in wildcard_str:
        return f"^{re.escape(wildcard_str)}$"
        
    escaped = re.escape(wildcard_str)
    r_val = escaped.replace(r'\*', '.*').replace(r'\?', '.')
    
    while '.*.*' in r_val:
        r_val = r_val.replace('.*.*', '.*')
        
    return f"^{r_val}$"
    
def main():
    router_cleaned = {}
    allocated_names = set()
    
    for policy_card in FILE_POLICY_ROUTER:
        raw_name = policy_card.get('name', '')
        real_name = get_smart_base_name(raw_name, policy_card, allocated_names)
        allocated_names.add(real_name)
        router_cleaned[real_name] = policy_card

    if os.path.exists(SOURCE_DIR):
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
                        except Exception:
                            pass
                    else:
                        try:
                            os.rename(old_path, new_path)
                        except Exception:
                            pass
                    f = new_f

                local_base_name = os.path.splitext(f)[0]
                if local_base_name in router_cleaned:
                    continue
                router_cleaned[local_base_name] = {
                    'name': local_base_name,
                    'url': []
                }

    global_matrix = {
        'qx': {}, 'sr': {}, 'mihomo': {}, 'singbox': {}, 'pac': {}
    }

    for target_base_name, policy_card in router_cleaned.items():
        rules_in_memory = fetch_and_merge_rules(target_base_name, policy_card)       
        dispatch_rules_to_targets(target_base_name, policy_card, rules_in_memory, global_matrix)
  
    # QuantumultX
    for g_name, g_rules in global_matrix['qx'].items():
        qx_path = os.path.join(QUANTUMULTX_DIR, f"{g_name}.list")
        qx_policy = g_rules['policy_label']
        optimize_domains(g_rules)
        with open(qx_path, 'w', encoding='utf-8') as f:
            f.write(f"# Quantumult X Aggregated Rule-Set: {g_name}\n\n")
            
            for val in sorted(g_rules['full']): f.write(f"host, {val}, {qx_policy}\n")
            for val in sorted(g_rules['suffix']): f.write(f"host-suffix, {val}, {qx_policy}\n")
            for val in sorted(g_rules['keyword']): f.write(f"host-keyword, {val}, {qx_policy}\n")
            for val in sorted(g_rules['ip']): f.write(f"ip-cidr, {ensure_ip_mask(val)}, {qx_policy}, no-resolve\n")
            for val in sorted(g_rules['ip6']): f.write(f"ip6-cidr, {ensure_ip_mask(val, True)}, {qx_policy}, no-resolve\n")
            for val in sorted(g_rules['useragent']):
                qx_ua = val
                if not ('*' in qx_ua or '?' in qx_ua):
                    qx_ua = f"*{qx_ua}*"
                if ',' in qx_ua:
                    qx_ua = f'"{qx_ua}"'
                f.write(f"user-agent, {qx_ua}, {qx_policy}\n")
        
            for val in sorted(g_rules['wildcard']): f.write(f"host-wildcard, {val}, {qx_policy}\n")
            for val in sorted(g_rules['regex']): f.write(f"host-regex, {val.strip()}, {qx_policy}\n")

    # Shadowrocket
    for g_name, g_rules in global_matrix['sr'].items():
        sr_path = os.path.join(SHADOWROCKET_DIR, f"{g_name}.list")
        optimize_domains(g_rules)
        with open(sr_path, 'w', encoding='utf-8') as f:
            f.write(f"# Shadowrocket Rule-Set: {g_name}\n\n")

            for val in sorted(list({str(p) for p in g_rules['port']})):
                if '-' in val or ':' in val:
                    continue
                f.write(f"DST-PORT,{val}\n")

            for val in sorted(g_rules['full']): f.write(f"DOMAIN,{val}\n")
            for val in sorted(g_rules['suffix']): f.write(f"DOMAIN-SUFFIX,{val}\n")
            for val in sorted(g_rules['keyword']): f.write(f"DOMAIN-KEYWORD,{val}\n")
            for val in sorted(g_rules['ip']): f.write(f"IP-CIDR,{ensure_ip_mask(val)},no-resolve\n")
            for val in sorted(g_rules['ip6']): f.write(f"IP-CIDR6,{ensure_ip_mask(val, True)},no-resolve\n")
            for val in sorted(g_rules['useragent']): f.write(f"USER-AGENT,{val}\n")
            for val in sorted(g_rules['wildcard']): f.write(f"DOMAIN-WILDCARD,{val}\n")
            for val in sorted(g_rules['regex']): f.write(f"DOMAIN-REGEX,{val}\n")

    # Mihomo 
    for g_name, g_rules in global_matrix['mihomo'].items():
        mihomo_path = os.path.join(MIHOMO_DIR, f"{g_name}.yaml")
        optimize_domains(g_rules)
        with open(mihomo_path, 'w', encoding='utf-8') as f:
            f.write(f"# Mihomo Payload Rule-Set: {g_name}\n")
            f.write("payload:\n")
            
            for val in sorted(g_rules['process']): f.write(f"  - PROCESS-NAME,{val}\n")
            for val in sorted(g_rules['port']): f.write(f"  - DST-PORT,{val}\n")
            for val in sorted(g_rules['full']): f.write(f"  - DOMAIN,{val}\n")
            for val in sorted(g_rules['suffix']): f.write(f"  - DOMAIN-SUFFIX,{val}\n")
            for val in sorted(g_rules['keyword']): f.write(f"  - DOMAIN-KEYWORD,{val}\n")
            for val in sorted(g_rules['ip']): f.write(f"  - IP-CIDR,{ensure_ip_mask(val)},no-resolve\n")
            for val in sorted(g_rules['ip6']): f.write(f"  - IP-CIDR6,{ensure_ip_mask(val, True)},no-resolve\n")
            for val in sorted(g_rules['wildcard']): f.write(f"  - DOMAIN-WILDCARD,{val}\n")            
            for val in sorted(g_rules['regex']): f.write(f"  - DOMAIN-REGEX,{val}\n")
    
    # Singbox
    for g_name, g_rules in global_matrix['singbox'].items():
        sb_path = os.path.join(SINGBOX_DIR, f"{g_name}.json")
        optimize_domains(g_rules)

        sb_data = {"version": 2, "rules": []}
        
        # 1. 组装独立的网络/域名族大区块 (利用同对象内的官方 OR 优化体积)
        net_block = {}
        
        if g_rules['full']: 
            net_block["domain"] = sorted(list(g_rules['full']))
        if g_rules['suffix']: 
            net_block["domain_suffix"] = sorted(list(g_rules['suffix']))
        if g_rules['keyword']: 
            net_block["domain_keyword"] = sorted(list(g_rules['keyword']))
            
        combined_ips = sorted(list(set([ensure_ip_mask(i) for i in g_rules['ip']] + [ensure_ip_mask(i, True) for i in g_rules['ip6'] ])))
        if combined_ips: 
            net_block["ip_cidr"] = combined_ips
            
        if g_rules['wildcard'] or g_rules['regex']:
            regex_list = [convert_wildcard_to_regex(w) for w in g_rules['wildcard']]
            for r in g_rules['regex']:
                regex_list.append(r)
            net_block["domain_regex"] = sorted(list(set(regex_list)))
            
        # 如果有域名或 IP 规则，作为一个独立对象放入数组
        if net_block:
            sb_data["rules"].append(net_block)

        # 2. 独立进程区块 (剥离出来，在外部形成全局 OR)
        if g_rules['process']: 
            sb_data["rules"].append({"process_name": sorted(list(g_rules['process']))})
            
        # 3. 独立端口区块 (剥离出来，在外部形成全局 OR)
        if g_rules['port']: 
            str_port_set = {str(p) for p in g_rules['port']}
            p_list, p_range = parse_ports_for_singbox(str_port_set)
            port_block = {}
            if p_list: port_block["port"] = p_list
            if p_range: port_block["port_range"] = p_range
            if port_block:
                sb_data["rules"].append(port_block)

        # 4. 复杂逻辑 AND 区块透传
        if g_rules.get('logical_and'):
            for and_rule in g_rules['logical_and']:
                sb_data["rules"].append(and_rule)
                
        # 写入文件
        with open(sb_path, 'w', encoding='utf-8') as f:
            json.dump(sb_data, f, indent=2, ensure_ascii=False)

    # PAC
    for g_name, g_domains in global_matrix['pac'].items():
        pac_path = os.path.join(PAC_DIR, f"{g_name}.pac")
        direct_domains = sorted(list(g_domains))
        with open(pac_path, 'w', encoding='utf-8') as f:
            f.write("var IP_ADDRESS = '127.0.0.1:7891';\n")
            f.write("var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; DIRECT';\n\n")
            f.write("var DIRECT_DOMAINS = {\n")
            for i, domain in enumerate(direct_domains):
                comma = "," if i < len(direct_domains) - 1 else ""
                f.write(f'    "{domain}": 1{comma}\n')
            f.write("};\n\n")
            f.write("function FindProxyForURL(url, host) {\n")
            f.write("    if (isPlainHostName(host) || /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {\n")
            f.write("        return \"DIRECT\";\n    }\n\n")
            f.write("    var suffix = host.toLowerCase();\n")
            f.write("    while (suffix) {\n")
            f.write("        if (DIRECT_DOMAINS.hasOwnProperty(suffix)) {\n")
            f.write("            return \"DIRECT\";\n")
            f.write("        }\n")
            f.write("        var pos = suffix.indexOf('.');\n")
            f.write("        if (pos === -1) break;\n")
            f.write("        suffix = suffix.substring(pos + 1);\n")
            f.write("    }\n\n")
            f.write("    return PROXY_METHOD;\n}\n")

if __name__ == '__main__':
    main()
