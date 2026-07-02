# -*- coding: utf-8 -*-
import os
import json
import re

SOURCE_DIR = 'source'
SHADOWROCKET_DIR = 'shadowrocket'
QUANTUMULTX_DIR = 'quantumultx'
CLASH_DIR = 'clash'
PAC_DIR = 'pac'
SINGBOX_DIR = 'singbox'

for d in [SOURCE_DIR, SHADOWROCKET_DIR, QUANTUMULTX_DIR, CLASH_DIR, PAC_DIR, SINGBOX_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

IPV4_REGEX = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
IPV6_REGEX = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d{1,3})?$')
DOMAIN_PATTERN = re.compile(r'^[a-z0-9\-]+\.[a-z0-9\-\.]+$')

PUBLIC_SUFFIX_BLACKLIST = {
    'com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'arpa', 'biz', 'info', 'name', 'pro',
    'app', 'dev', 'shop', 'club', 'top', 'xyz', 'vip', 'fun', 'site', 'online', 'tech', 'store',
    'work', 'live', 'link', 'icu', 'ltd', 'art', 'blog', 'news', 'wiki', 'chat', 'space', 'me',
    'cn', 'hk', 'tw', 'mo', 'jp', 'kr', 'sg', 'my', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'ru',
    'ai', 'io', 'co', 'so', 'to', 'do', 'in', 'cc', 'tv', 'me', 'la', 'fm', 'am', 'im', 'gg',
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

def clean_and_parse_line(line):
    line = line.strip()
    if not line or line.startswith(('#', '//', ';')) or line == 'payload:':
        return None, None
        
    line = line.split('#')[0].split('//')[0].strip()
    
    if line.startswith('-'):
        line = line.lstrip('-').strip()
    line = line.replace("'", "").replace('"', "")
    if not line:
        return None, None

    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2:
            return None, None
        p1 = parts[0].upper()
        p2 = parts[1]
        
        if p1 in ['AND', 'OR', 'NOT']:
            return None, None
        if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']: 
            return 'suffix', p2.replace('*.', '', 1).lstrip('.').lower()
        if p1 in ['DOMAIN', 'HOST', 'FULL']: 
            p2 = p2.lower()
            if p2.startswith('*.'): return 'suffix', p2[2:].lstrip('.')
            if '*' in p2 or '?' in p2: return 'wildcard', p2
            return 'full', p2
        if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']: 
            return 'keyword', p2.lower()
        if p1 in ['DOMAIN-WILDCARD', 'HOST-WILDCARD', 'WILDCARD']:
            return 'wildcard', p2.lower()
        if p1 in ['IP-CIDR', 'IP']: return 'ip', p2
        if p1 in ['IP-CIDR6', 'IP6-CIDR', 'IP6']: return 'ip6', p2
        if p1 in ['PROCESS-NAME', 'PROCESS']: return 'process', p2
        if p1 in ['USER-AGENT', 'USERAGENT']: return 'useragent', p2
        if p1 in ['DST-PORT', 'PORT']: return 'port', p2
        if p1 in ['GEOIP']: return 'geoip', p2.upper()
        return None, None

    raw_val = line.lower()
    
    if IPV4_REGEX.match(raw_val):
        return 'ip', raw_val
    if IPV6_REGEX.match(raw_val):
        return 'ip6', raw_val
        
    is_explicit_suffix = False
    
    if raw_val.startswith('+.'): 
        raw_val = raw_val[2:]
        is_explicit_suffix = True
    elif raw_val.startswith('*.'): 
        raw_val = raw_val[2:]
        is_explicit_suffix = True
    elif raw_val.startswith('.'): 
        raw_val = raw_val[1:]
        is_explicit_suffix = True
    elif raw_val.startswith('+'): 
        raw_val = raw_val[1:]
        is_explicit_suffix = True
    
    raw_val = raw_val.lstrip('.')
    if not raw_val:
        return None, None
        
    if '*' in raw_val or '?' in raw_val:
        return 'wildcard', raw_val
        
    if is_explicit_suffix:
        return 'suffix', raw_val
    else:
        if DOMAIN_PATTERN.match(raw_val):
            if raw_val in PUBLIC_SUFFIX_BLACKLIST:
                return None, None
            
            parts = raw_val.split('.')
            parts_count = len(parts)
            last_2_parts = '.'.join(parts[-2:]) if parts_count >= 2 else ''
            is_compound_public = last_2_parts in PUBLIC_SUFFIX_BLACKLIST
            
            if parts_count == 2:
                return 'suffix', raw_val
            elif parts_count == 3 and is_compound_public:
                return 'suffix', raw_val
            else:
                return 'full', raw_val
        else:
            return 'full', raw_val

def optimize_domains(rules):
    if rules['suffix']:
        reversed_domains = sorted(['.'.join(reversed(d.split('.'))) + '.' for d in rules['suffix']])
        
        clean_reversed = []
        for rd in reversed_domains:
            if not clean_reversed or not rd.startswith(clean_reversed[-1]):
                clean_reversed.append(rd)
        
        rules['suffix'] = {'.'.join(reversed(rd.rstrip('.').split('.'))) for rd in clean_reversed}

    if rules['full'] and rules['suffix']:
        clean_full = set()
        for domain in rules['full']:
            is_covered = False
            parts = domain.split('.')
            for i in range(len(parts)):
                parent = '.'.join(parts[i:])
                if parent in rules['suffix']:
                    is_covered = True
                    break
            if not is_covered:
                clean_full.add(domain)
        rules['full'] = clean_full

def process_file(file_name):
    source_path = os.path.join(SOURCE_DIR, file_name)
    base_name = os.path.splitext(file_name)[0]
    file_keyword = base_name.lower()
    rules = {
        'suffix': set(), 'full': set(), 'keyword': set(), 'wildcard': set(),
        'ip': set(), 'ip6': set(), 'process': set(), 'useragent': set(),
        'port': set(), 'geoip': set()
    }
    with open(source_path, 'r', encoding='utf-8') as f:
        for line in f:
            rule_type, value = clean_and_parse_line(line)
            if rule_type in rules:
                rules[rule_type].add(value)
    optimize_domains(rules)

    # 1. Source
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} Sorted Rules ===\n\n")
        for r_type in ['suffix', 'full', 'keyword', 'wildcard', 'ip', 'ip6', 'process', 'useragent', 'port', 'geoip']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")

    # 2. Shadowrocket
    sr_path = os.path.join(SHADOWROCKET_DIR, f"{base_name}.list")
    with open(sr_path, 'w', encoding='utf-8') as f_sr:
        f_sr.write(f"# Shadowrocket Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_sr.write(f"DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_sr.write(f"DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_sr.write(f"DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['wildcard']): f_sr.write(f"DOMAIN-WILDCARD,{val}\n")
        for val in sorted(rules['useragent']): f_sr.write(f"USER-AGENT,{val}\n")
        for val in sorted(rules['port']): f_sr.write(f"DST-PORT,{val}\n")
        for val in sorted(rules['geoip']): f_sr.write(f"GEOIP,{val}\n")
        for val in sorted(rules['ip']): f_sr.write(f"IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_sr.write(f"IP-CIDR6,{val},no-resolve\n")

    # 3. Quantumult X
    qx_path = os.path.join(QUANTUMULTX_DIR, f"{base_name}.list")
    if file_keyword == 'direct': qx_policy = 'direct'
    elif file_keyword == 'reject': qx_policy = 'reject'
    else: qx_policy = base_name.capitalize()
    with open(qx_path, 'w', encoding='utf-8') as f_qx:
        f_qx.write(f"# Quantumult X Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_qx.write(f"host-suffix, {val}, {qx_policy}\n")
        for val in sorted(rules['full']): f_qx.write(f"host, {val}, {qx_policy}\n")
        for val in sorted(rules['keyword']): f_qx.write(f"host-keyword, {val}, {qx_policy}\n")
        for val in sorted(rules['wildcard']): f_qx.write(f"host-wildcard, {val}, {qx_policy}\n")
        for val in sorted(rules['port']): f_qx.write(f"dest-port, {val}, {qx_policy}\n")
        for val in sorted(rules['geoip']): f_qx.write(f"geoip, {val}, {qx_policy}\n")
        for val in sorted(rules['useragent']): 
            qx_ua = val if ('*' in val or '?' in val) else f"*{val}*"
            f_qx.write(f"user-agent, {qx_ua}, {qx_policy}\n")
        for val in sorted(rules['ip']): f_qx.write(f"ip-cidr, {val}, {qx_policy}, no-resolve\n")
        for val in sorted(rules['ip6']): f_qx.write(f"ip6-cidr, {val}, {qx_policy}, no-resolve\n")

    # 4. Clash
    clash_path = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(clash_path, 'w', encoding='utf-8') as f_clash:
        f_clash.write(f"# Clash Payload Rule-Set: {base_name}\n")
        f_clash.write("payload:\n")
        for val in sorted(rules['suffix']): f_clash.write(f"  - DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_clash.write(f"  - DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_clash.write(f"  - DOMAIN-KEYWORD,{val}\n")       
        for val in sorted(rules['process']): f_clash.write(f"  - PROCESS-NAME,{val}\n")
        for val in sorted(rules['port']): f_clash.write(f"  - DST-PORT,{val}\n")
        for val in sorted(rules['geoip']): f_clash.write(f"  - GEOIP,{val}\n")
        for val in sorted(rules['ip']): f_clash.write(f"  - IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_clash.write(f"  - IP-CIDR6,{val},no-resolve\n")

    # 5. PAC
    if file_keyword in ['direct', 'china']:
        pac_path = os.path.join(PAC_DIR, "direct.pac")
        with open(pac_path, 'w', encoding='utf-8') as f_pac:
            direct_domains = sorted(list(rules['suffix'].union(rules['full'])))
            f_pac.write("var IP_ADDRESS = '127.0.0.1:7891';\n")
            f_pac.write("var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; DIRECT';\n\n")
            f_pac.write("var DIRECT_DOMAINS = {\n")
            for i, domain in enumerate(direct_domains):
                comma = "," if i < len(direct_domains) - 1 else ""
                f_pac.write(f'    "{domain}": 1{comma}\n')
            f_pac.write("};\n\n")
            f_pac.write("function FindProxyForURL(url, host) {\n")
            f_pac.write("    if (isPlainHostName(host) || /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {\n")
            f_pac.write("        return \"DIRECT\";\n    }\n\n")
            f_pac.write("    var suffix = host;\n")
            f_pac.write("    while (suffix) {\n")
            f_pac.write("        if (DIRECT_DOMAINS.hasOwnProperty(suffix)) {\n")
            f_pac.write("            return \"DIRECT\";\n")
            f_pac.write("        }\n")
            f_pac.write("        var pos = suffix.indexOf('.');\n")
            f_pac.write("        if (pos === -1) break;\n")
            f_pac.write("        suffix = suffix.substring(pos + 1);\n")
            f_pac.write("    }\n\n")
            f_pac.write("    return PROXY_METHOD;\n}\n")

    # 6. Sing-box
    sb_path = os.path.join(SINGBOX_DIR, f"{base_name}.json")
    sb_data = {"version": 1, "rules": []}
    sub_rule = {}
    if rules['suffix']: sub_rule["domain_suffix"] = sorted(list(rules['suffix']))
    if rules['full']: sub_rule["domain"] = sorted(list(rules['full']))
    if rules['keyword']: sub_rule["domain_keyword"] = sorted(list(rules['keyword']))
    if rules['process']: sub_rule["process_name"] = sorted(list(rules['process']))
    if rules['useragent']: sub_rule["user_agent"] = sorted(list(rules['useragent']))
    if rules['geoip']: sub_rule["country"] = sorted(list(rules['geoip']))
    if rules['port']: sub_rule["port"] = sorted([int(p) for p in rules['port']])
    if rules['wildcard']:
        regex_list = []
        for w in rules['wildcard']:
            r = f"^{w.replace('.', '\\.').replace('*', '.*').replace('?', '.')}$"
            regex_list.append(r)
        sub_rule["domain_regex"] = regex_list
    combined_ips = sorted(list(rules['ip'].union(rules['ip6'])))
    if combined_ips: sub_rule["ip_cidr"] = combined_ips
    if sub_rule: sb_data["rules"].append(sub_rule)
    with open(sb_path, 'w', encoding='utf-8') as f_sb:
        json.dump(sb_data, f_sb, indent=2, ensure_ascii=False)

    # 7. Binary Templates
    if 'classic' in file_keyword:
        return

    if 'ip' in file_keyword:
        combined_ips = sorted(list(rules['ip'].union(rules['ip6'])))
        if combined_ips:
            with open(os.path.join(CLASH_DIR, f"tmp_ip_{base_name}.yaml"), 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for item in combined_ips: 
                    f.write(f"  - '{item}'\n")
            sb_tmp_ip = {"version": 1, "rules": [{"ip_cidr": combined_ips}]}
            with open(os.path.join(SINGBOX_DIR, f"tmp_ip_{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sb_tmp_ip, f, indent=2, ensure_ascii=False)
    else:
        sb_tmp_domain = {"version": 1, "rules": []}
        sub_dm_rule = {}
        if rules['suffix']: sub_dm_rule["domain_suffix"] = sorted(list(rules['suffix']))
        if rules['full']: sub_dm_rule["domain"] = sorted(list(rules['full']))
        if rules['keyword']: sub_dm_rule["domain_keyword"] = sorted(list(rules['keyword']))
        if rules['port']: sub_dm_rule["port"] = sorted([int(p) for p in rules['port']])
        if rules['wildcard']:
            regex_list = []
            for w in rules['wildcard']:
                r = f"^{w.replace('.', '\\.').replace('*', '.*').replace('?', '.')}$"
                regex_list.append(r)
            sub_dm_rule["domain_regex"] = regex_list
        if sub_dm_rule:
            sb_tmp_domain["rules"].append(sub_dm_rule)
            with open(os.path.join(SINGBOX_DIR, f"tmp_domain_{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sb_tmp_domain, f, indent=2, ensure_ascii=False)
        if rules['suffix'] or rules['full']:
            with open(os.path.join(CLASH_DIR, f"tmp_domain_{base_name}.yaml"), 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for item in sorted(rules['suffix']): f.write(f"  - '.{item}'\n")
                for item in sorted(rules['full']): f.write(f"  - '{item}'\n")

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Directory '{SOURCE_DIR}' not found. Please create it and add your .txt files.")
        return
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        print(f"Processing {file_name}...")
        process_file(file_name)
    print("Done! All rules have been parsed and generated.")

if __name__ == '__main__':
    main()
