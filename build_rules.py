# -*- coding: utf-8 -*-
import os
import json

SOURCE_DIR = 'source'
SHADOWROCKET_DIR = 'shadowrocket'
QUANTUMULTX_DIR = 'quantumultx'
CLASH_DIR = 'clash'
PAC_DIR = 'pac'
SINGBOX_DIR = 'singbox'

for d in [SOURCE_DIR, SHADOWROCKET_DIR, QUANTUMULTX_DIR, CLASH_DIR, PAC_DIR, SINGBOX_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

def clean_and_parse_line(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
        return None, None
        
    if line.startswith('-'):
        line = line.lstrip('-').strip()
        
    line = line.replace("'", "").replace('"', "")
        
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

    if '/' in line and any(c.isdigit() for c in line):
        return 'ip6' if ':' in line else 'ip', line

    if line.startswith('.'):
        return 'suffix', line.lstrip('.').lower()
    if line.startswith('*.'):
        return 'suffix', line[2:].lstrip('.').lower()
            
    return 'suffix', line.lower()

def optimize_domains(rules):
    sorted_suffixes = sorted(list(rules['suffix']), key=len)
    clean_suffixes = set()
    for domain in sorted_suffixes:
        is_subdomain = False
        for clean in clean_suffixes:
            if domain == clean or domain.endswith('.' + clean):
                is_subdomain = True
                break
        if not is_subdomain:
            clean_suffixes.add(domain)
            
    rules['suffix'] = clean_suffixes
    clean_full = set()
    for domain in rules['full']:
        is_covered = False
        for clean in rules['suffix']:
            if domain == clean or domain.endswith('.' + clean):
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
                
    # 1. Source 备份输出
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} Sorted Rules ===\n\n")
        for r_type in ['suffix', 'full', 'keyword', 'wildcard', 'ip', 'ip6', 'process', 'useragent', 'port', 'geoip']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
    # 2. Shadowrocket 小火箭规范输出
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

    # 3. Quantumult X 规范输出
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

    # 4. Clash Classical 规则集输出（100% 还原官方明文无引号规范）
    clash_path = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(clash_path, 'w', encoding='utf-8') as f_clash:
        f_clash.write(f"# Clash Payload Rule-Set: {base_name}\n")
        f_clash.write("payload:\n")
        for val in sorted(rules['suffix']): f_clash.write(f"  - DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_clash.write(f"  - DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_clash.write(f"  - DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['wildcard']): f_clash.write(f"  - DOMAIN,{val}\n") 
        for val in sorted(rules['process']): f_clash.write(f"  - PROCESS-NAME,{val}\n")
        for val in sorted(rules['port']): f_clash.write(f"  - DST-PORT,{val}\n")
        for val in sorted(rules['geoip']): f_clash.write(f"  - GEOIP,{val}\n")
        for val in sorted(rules['ip']): f_clash.write(f"  - IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_clash.write(f"  - IP-CIDR6,{val},no-resolve\n")

    # 5. PAC 输出
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

    # 6. Sing-box JSON 规范输出
    sb_path = os.path.join(SINGBOX_DIR, f"{base_name}.json")
    sb_data = {"version": 1, "rules": []}
    sub_rule = {}
    if rules['suffix']: sub_rule["domain_suffix"] = sorted(list(rules['suffix']))
    if rules['full']: sub_rule["domain"] = sorted(list(rules['full']))
    if rules['keyword']: sub_rule["domain_keyword"] = sorted(list(rules['keyword']))
    if rules['process']: sub_rule["process_name"] = sorted(list(rules['process']))
    if rules['useragent']: sub_rule["user_agent"] = sorted(list(rules['useragent']))
    if rules['geoip']: sub_rule["country"] = sorted(list(rules['geoip']))
    
    if rules['port']:
        ports_list = []
        for p in rules['port']:
            if '-' in p: ports_list.append(p)
            elif p.isdigit(): ports_list.append(int(p))
        if ports_list: sub_rule["port"] = ports_list
        
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

    # 7. 二进制规则编译预处理引擎（保持包含 'ip' 关键字的安全分流逻辑）
    if 'classic' in file_keyword:
        return

    if 'ip' in file_keyword:
        combined_ips = sorted(list(rules['ip'].union(rules['ip6'])))
        if combined_ips:
            # 【完美对齐官方 ipcidr 规范】纯 IP 规则集必须加单引号
            with open(os.path.join(CLASH_DIR, f"tmp_ip_{base_name}.yaml"), 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for item in combined_ips: 
                    f.write(f"  - '{item}'\n")
            
            sb_tmp_ip = {"version": 1, "rules": [{"ip_cidr": combined_ips}]}
            with open(os.path.join(SINGBOX_DIR, f"tmp_ip_{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sb_tmp_ip, f, indent=2, ensure_ascii=False)
            print(f"--> [IP MODE] Created strict binary templates for: {file_name}")
            
    else:
        if rules['suffix'] or rules['full']:
            # 【完美对齐官方 domain 规范】后缀强制前缀点号，不带前缀符号
            with open(os.path.join(CLASH_DIR, f"tmp_domain_{base_name}.yaml"), 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for item in sorted(rules['suffix']):
                    f.write(f"  - '.{item}'\n")
                for item in sorted(rules['full']):
                    f.write(f"  - '{item}'\n")
            
            sb_tmp_domain = {"version": 1, "rules": []}
            sub_dm_rule = {}
            if rules['suffix']: sub_dm_rule["domain_suffix"] = sorted(list(rules['suffix']))
            if rules['full']: sub_dm_rule["domain"] = sorted(list(rules['full']))
            if sub_dm_rule: sb_tmp_domain["rules"].append(sub_dm_rule)
            
            with open(os.path.join(SINGBOX_DIR, f"tmp_domain_{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sb_tmp_domain, f, indent=2, ensure_ascii=False)
            print(f"--> [DOMAIN MODE] Created strict binary templates for: {file_name}")

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Error: SOURCE_DIR '{SOURCE_DIR}' not found.")
        return
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        process_file(file_name)

if __name__ == '__main__':
    main()
