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
    
    # 【原则 1】：保持现有的注释过滤逻辑不变！
    if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
        return None, None
        
    if line.startswith('-'):
        line = line.lstrip('-').strip()
        
    line = line.replace("'", "").replace('"', "")
        
    # 【原则 3】：保持向前兼容（解析带逗号标签的规则）
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2:
            return None, None
            
        p1 = parts[0].upper()
        p2 = parts[1]
        
        if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']: return 'suffix', p2.lstrip('.').lower()
        if p1 in ['DOMAIN', 'HOST', 'FULL']: return 'full', p2.lower()
        if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']: return 'keyword', p2.lower()
        
        if p1 in ['IP-CIDR', 'IP']: return 'ip', p2
        if p1 in ['IP-CIDR6', 'IP6-CIDR', 'IP6']: return 'ip6', p2

        if p1 in ['PROCESS-NAME', 'PROCESS']: return 'process', p2
        if p1 in ['USER-AGENT', 'USERAGENT']: return 'useragent', p2
            
        return None, None

    # 保持向前兼容：纯 IP 带掩码情况
    if '/' in line and any(c.isdigit() for c in line):
        return 'ip6' if ':' in line else 'ip', line

    # 【修改要求 1 & 2】：只要文本是以 . 开头，一律剥离首位的 . 并直接归类为 'suffix'
    # 彻底删掉了通过计算点的数量（value.count('.') >= 2）来划分 'full' 的死板逻辑！
    if line.startswith('.'):
        value = line.lstrip('.').lower()
        return 'suffix', value
            
    # 保持向前兼容：处理无标签纯域名等（原逻辑直接归为 suffix）
    return 'suffix', line.lstrip('.').lower()

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
    rules = {'suffix': set(), 'full': set(), 'keyword': set(), 'ip': set(), 'ip6': set(), 'process': set(), 'useragent': set()}
    
    # 临时读取内容
    with open(source_path, 'r', encoding='utf-8') as f:
        for line in f:
            rule_type, value = clean_and_parse_line(line)
            if rule_type in rules:
                rules[rule_type].add(value)
                
    optimize_domains(rules)
                
    # 1. 回写 source（保持您原版的格式化逻辑）
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} Original Rules ===\n\n")
        for r_type in ['suffix', 'full', 'keyword', 'ip', 'ip6', 'process', 'useragent']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
    # 2. 生成 shadowrocket 规则
    sr_path = os.path.join(SHADOWROCKET_DIR, f"{base_name}.list")
    with open(sr_path, 'w', encoding='utf-8') as f_sr:
        f_sr.write(f"# Shadowrocket Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_sr.write(f"DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_sr.write(f"DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_sr.write(f"DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['useragent']): f_sr.write(f"USER-AGENT,{val}\n")
        for val in sorted(rules['ip']): f_sr.write(f"IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_sr.write(f"IP-CIDR6,{val},no-resolve\n")

    # 3. 生成 QuantumultX 规则
    qx_path = os.path.join(QUANTUMULTX_DIR, f"{base_name}.list")
    if base_name.lower() == 'direct': qx_policy = 'DIRECT'
    elif base_name.lower() == 'reject': qx_policy = 'REJECT'
    else: qx_policy = base_name.capitalize()
        
    with open(qx_path, 'w', encoding='utf-8') as f_qx:
        f_qx.write(f"# Quantumult X Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_qx.write(f"host-suffix, {val}, {qx_policy}\n")
        for val in sorted(rules['full']): f_qx.write(f"host, {val}, {qx_policy}\n")
        for val in sorted(rules['keyword']): f_qx.write(f"host-keyword, {val}, {qx_policy}\n")
        for val in sorted(rules['useragent']): f_qx.write(f"user-agent, {val}, {qx_policy}\n")
        for val in sorted(rules['ip']): f_qx.write(f"ip-cidr, {val}, {qx_policy}, no-resolve\n")
        for val in sorted(rules['ip6']): f_qx.write(f"ip6-cidr, {val}, {qx_policy}, no-resolve\n")

    # 4. 生成 Clash 经典规则
    clash_path = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(clash_path, 'w', encoding='utf-8') as f_clash:
        f_clash.write(f"# Clash Payload Rule-Set: {base_name}\n")
        f_clash.write("payload:\n")
        for val in sorted(rules['suffix']): f_clash.write(f"  - DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_clash.write(f"  - DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_clash.write(f"  - DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['process']): f_clash.write(f"  - PROCESS-NAME,{val}\n")
        for val in sorted(rules['ip']): f_clash.write(f"  - IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_clash.write(f"  - IP-CIDR6,{val},no-resolve\n")

    # 5. 生成 PAC 规则
    if base_name.lower() == 'direct':
        pac_path = os.path.join(PAC_DIR, f"{base_name}.pac")
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

    # 6. 生成 sing-box 规则
    sb_path = os.path.join(SINGBOX_DIR, f"{base_name}.json")
    sb_data = {"version": 1, "rules": []}
    sub_rule = {}
    if rules['suffix']: sub_rule["domain_suffix"] = sorted(list(rules['suffix']))
    if rules['full']: sub_rule["domain"] = sorted(list(rules['full']))
    if rules['keyword']: sub_rule["domain_keyword"] = sorted(list(rules['keyword']))
    if rules['process']: sub_rule["process_name"] = sorted(list(rules['process']))
    
    combined_ips = sorted(list(rules['ip'].union(rules['ip6'])))
    if combined_ips: sub_rule["ip_cidr"] = combined_ips
    
    if sub_rule: sb_data["rules"].append(sub_rule)
        
    with open(sb_path, 'w', encoding='utf-8') as f_sb:
        json.dump(sb_data, f_sb, indent=2, ensure_ascii=False)

    # 7. 追加：为 Actions 编译 Mihomo MRS 铺垫纯净的临时过渡文件
    clash_domains = [f"+.{val}" for val in sorted(rules['suffix'])] + sorted(list(rules['full']))
    if clash_domains:
        with open(os.path.join(CLASH_DIR, f"tmp_{base_name}_domain.yaml"), 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for item in clash_domains: f.write(f"  - '{item}'\n")

    if combined_ips:
        with open(os.path.join(CLASH_DIR, f"tmp_{base_name}_ipcidr.yaml"), 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for item in combined_ips: f.write(f"  - '{item}'\n")

    print(f"Success: {file_name} compiled.")

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Error: SOURCE_DIR '{SOURCE_DIR}' not found.")
        return
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        process_file(file_name)

if __name__ == '__main__':
    main()
