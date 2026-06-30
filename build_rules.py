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
        p1 = parts[0].upper()
        p2 = parts[1]
        
        if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']:
            return 'suffix', p2.lstrip('.')
        if p1 in ['DOMAIN', 'HOST', 'FULL']:
            return 'full', p2
        if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']:
            return 'keyword', p2
        if p1 in ['IP-CIDR', 'IP-CIDR6', 'IP']:
            return 'ip', p2
            
        if p1.lower() in ['suffix', 'full', 'keyword', 'ip']:
            val = p2.lstrip('.') if p1.lower() in ['suffix', 'full'] else p2
            return p1.lower(), val

    if line.startswith('.'):
        value = line.lstrip('.')
        return ('full', value) if value.count('.') >= 2 else ('suffix', value)
            
    if '/' in line and any(c.isdigit() for c in line):
        return 'ip', line

    return 'suffix', line.lstrip('.')

def process_file(file_name):
    source_path = os.path.join(SOURCE_DIR, file_name)
    base_name = os.path.splitext(file_name)[0]
    rules = {'suffix': set(), 'full': set(), 'keyword': set(), 'ip': set()}
    
    with open(source_path, 'r', encoding='utf-8') as f:
        for line in f:
            rule_type, value = clean_and_parse_line(line)
            if rule_type in rules:
                rules[rule_type].add(value)
                
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} Original Rules ===\n\n")
        for r_type in ['suffix', 'full', 'keyword', 'ip']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
    sr_path = os.path.join(SHADOWROCKET_DIR, f"{base_name}.list")
    with open(sr_path, 'w', encoding='utf-8') as f_sr:
        f_sr.write(f"# Shadowrocket Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_sr.write(f"DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_sr.write(f"DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_sr.write(f"DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['ip']): f_sr.write(f"IP-CIDR,{val},no-resolve\n")

    qx_path = os.path.join(QUANTUMULTX_DIR, f"{base_name}.list")
    with open(qx_path, 'w', encoding='utf-8') as f_qx:
        f_qx.write(f"# Quantumult X Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_qx.write(f"HOST-SUFFIX,{val},DIRECT\n")
        for val in sorted(rules['full']): f_qx.write(f"HOST,{val},DIRECT\n")
        for val in sorted(rules['keyword']): f_qx.write(f"HOST-KEYWORD,{val},DIRECT\n")
        for val in sorted(rules['ip']): f_qx.write(f"IP-CIDR,{val},DIRECT\n")

    clash_path = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(clash_path, 'w', encoding='utf-8') as f_clash:
        f_clash.write(f"# Clash Payload Rule-Set: {base_name}\n")
        f_clash.write("payload:\n")
        for val in sorted(rules['suffix']): f_clash.write(f"  - DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_clash.write(f"  - DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_clash.write(f"  - DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['ip']): f_clash.write(f"  - IP-CIDR,{val},no-resolve\n")

    pac_path = os.path.join(PAC_DIR, f"{base_name}.pac")
    with open(pac_path, 'w', encoding='utf-8') as f_pac:
        direct_domains = sorted(list(rules['suffix'].union(rules['full'])))
        f_pac.write("var IP_ADDRESS = '127.0.0.1:7891';\n")
        f_pac.write("var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS;\n\n")
        f_pac.write("var RULES = [\n    [\n")
        for i, domain in enumerate(direct_domains):
            comma = "," if i < len(direct_domains) - 1 else ""
            f_pac.write(f'        "{domain}"{comma}\n')
        f_pac.write("    ]\n];\n\n")
        f_pac.write('var DIRECT_DOMAINS = {\n    "cn": 1\n};\n\n')
        f_pac.write("(function init() {\n    if (!RULES) return;\n    for (var j = 0; j < RULES.length; j++) {\n")
        f_pac.write("        var rules = RULES[j];\n        if (!rules) continue;\n")
        f_pac.write("        for (var i = 0; i < rules.length; i++) {\n            var domain = rules[i];\n")
        f_pac.write("            if (domain) {\n                DIRECT_DOMAINS[domain] = 1;\n            }\n        }\n    }\n    RULES = null;\n})();\n\n")
        f_pac.write("function FindProxyForURL(url, host) {\n    if (isPlainHostName(host)) {\n        return \"DIRECT\";\n    }\n\n")
        f_pac.write("    if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) {\n        return \"DIRECT\";\n    }\n\n")
        f_pac.write("    var suffix = host;\n    while (true) {\n        if (DIRECT_DOMAINS[suffix] === 1) {\n            return \"DIRECT\";\n        }\n        var pos = suffix.indexOf('.');\n        if (pos <= 0) {\n            break;\n        }\n        suffix = suffix.substring(pos + 1);\n    }\n\n    return PROXY_METHOD;\n}\n")

    # Output sing-box rule_set (.json)
    sb_path = os.path.join(SINGBOX_DIR, f"{base_name}.json")
    sb_data = {
        "version": 1,
        "rules": []
    }
    sub_rule = {}
    if rules['suffix']: sub_rule["domain_suffix"] = sorted(list(rules['suffix']))
    if rules['full']: sub_rule["domain"] = sorted(list(rules['full']))
    if rules['keyword']: sub_rule["domain_keyword"] = sorted(list(rules['keyword']))
    if rules['ip']: sub_rule["ip_cidr"] = sorted(list(rules['ip']))
    
    if sub_rule:
        sb_data["rules"].append(sub_rule)
        
    with open(sb_path, 'w', encoding='utf-8') as f_sb:
        json.dump(sb_data, f_sb, indent=2, ensure_ascii=False)

    print(f"Success: {file_name} compiled.")

def main():
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        process_file(file_name)

if __name__ == '__main__':
    main()
