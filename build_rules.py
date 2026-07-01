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
    # 原则 1：严格保持现有的注释过滤逻辑不变
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
        
        if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']: return 'suffix', p2.lstrip('.').lower()
        if p1 in ['DOMAIN', 'HOST', 'FULL']: return 'full', p2.lower()
        if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']: return 'keyword', p2.lower()
        if p1 in ['IP-CIDR', 'IP']: return 'ip', p2
        if p1 in ['IP-CIDR6', 'IP6-CIDR', 'IP6']: return 'ip6', p2
        if p1 in ['PROCESS-NAME', 'PROCESS']: return 'process', p2
        if p1 in ['USER-AGENT', 'USERAGENT']: return 'useragent', p2
        return None, None

    if '/' in line and any(c.isdigit() for c in line):
        return 'ip6' if ':' in line else 'ip', line

    # 修改要求 1：以 . 开头一律剥离并归类为 'suffix'
    if line.startswith('.'):
        return 'suffix', line.lstrip('.').lower()
            
    # 修改要求 2：剔除点数计算死板逻辑，无标签纯域名默认向下兼容作为 'suffix'
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
    
    rules = {'suffix': set(), 'full': set(), 'keyword': set(), 'ip': set(), 'ip6': set(), 'process': set(), 'useragent': set()}
    
    with open(source_path, 'r', encoding='utf-8') as f:
        for line in f:
            rule_type, value = clean_and_parse_line(line)
            if rule_type in rules:
                rules[rule_type].add(value)
                
    optimize_domains(rules)
                
    # 1. Source Output
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} Original Rules ===\n\n")
        for r_type in ['suffix', 'full', 'keyword', 'ip', 'ip6', 'process', 'useragent']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
    # 2. Shadowrocket Output
    sr_path = os.path.join(SHADOWROCKET_DIR, f"{base_name}.list")
    with open(sr_path, 'w', encoding='utf-8') as f_sr:
        f_sr.write(f"# Shadowrocket Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_sr.write(f"DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_sr.write(f"DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_sr.write(f"DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['useragent']): f_sr.write(f"USER-AGENT,{val}\n")
        for val in sorted(rules['ip']): f_sr.write(f"IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_sr.write(f"IP-CIDR6,{val},no-resolve\n")

    # 3. QuantumultX Output
    qx_path = os.path.join(QUANTUMULTX_DIR, f"{base_name}.list")
    if file_keyword == 'direct': qx_policy = 'DIRECT'
    elif file_keyword == 'reject': qx_policy = 'REJECT'
    else: qx_policy = base_name.capitalize()
        
    with open(qx_path, 'w', encoding='utf-8') as f_qx:
        f_qx.write(f"# Quantumult X Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_qx.write(f"host-suffix, {val}, {qx_policy}\n")
        for val in sorted(rules['full']): f_qx.write(f"host, {val}, {qx_policy}\n")
        for val in sorted(rules['keyword']): f_qx.write(f"host-keyword, {val}, {qx_policy}\n")
        for val in sorted(rules['useragent']): f_qx.write(f"user-agent, {val}, {qx_policy}\n")
        for val in sorted(rules['ip']): f_qx.write(f"ip-cidr, {val}, {qx_policy}, no-resolve\n")
        for val in sorted(rules['ip6']): f_qx.write(f"ip6-cidr, {val}, {qx_policy}, no-resolve\n")

    # 4. Clash Output
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

    # 5. PAC Output
    if file_keyword == 'direct':
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

    # 6. Sing-box Standard JSON Output
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

    # 7. 全新精修：多模式二机制规则编译引擎
    # 原则 1：名称内包含 'classic' 则 100% 拒绝转换二进制
    if 'classic' in file_keyword:
        print(f"--> [CLASSIC SKIP] Fulfill matrix rule: {file_name} has NO binary output.")
        return

    # 原则 2：只有名称内包含 'ip' 或 'IP'，才执行纯 IP-CIDR 转换
    if 'ip' in file_keyword:
        combined_ips = sorted(list(rules['ip'].union(rules['ip6'])))
        if combined_ips:
            # 建立带有分类前缀的临时文件，给下游 Actions 识别编译类别
            with open(os.path.join(CLASH_DIR, f"tmp_ip_{base_name}.yaml"), 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for item in combined_ips: f.write(f"  - '{item}'\n")
            
            sb_tmp_ip = {"version": 1, "rules": [{"ip_cidr": combined_ips}]}
            with open(os.path.join(SINGBOX_DIR, f"tmp_ip_{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sb_tmp_ip, f, indent=2, ensure_ascii=False)
            print(f"--> [IP MODE] Prepared binary template for: {file_name}")
            
    # 原则 3：其余所有普通规则（如 apple.txt），正常执行 Domain 模式转换（丢失/剥离IP段）
    else:
        if rules['suffix'] or rules['full']:
            # Mihomo Domain 规则集的 payload 必须是不带标签的纯域名列表
            # 融合规则集内的有效后缀及全域名
            combined_domains = sorted(list(rules['suffix'].union(rules['full'])))
            with open(os.path.join(CLASH_DIR, f"tmp_domain_{base_name}.yaml"), 'w', encoding='utf-8') as f:
                f.write("payload:\n")
                for item in combined_domains: f.write(f"  - '{item}'\n")
            
            # Sing-box Domain 模式 JSON（不包含任何 IP 规则字段）
            sb_tmp_domain = {"version": 1, "rules": []}
            sub_dm_rule = {}
            if rules['suffix']: sub_dm_rule["domain_suffix"] = sorted(list(rules['suffix']))
            if rules['full']: sub_dm_rule["domain"] = sorted(list(rules['full']))
            if sub_dm_rule: sb_tmp_domain["rules"].append(sub_dm_rule)
            
            with open(os.path.join(SINGBOX_DIR, f"tmp_domain_{base_name}.json"), 'w', encoding='utf-8') as f:
                json.dump(sb_tmp_domain, f, indent=2, ensure_ascii=False)
            print(f"--> [DOMAIN MODE] Prepared binary template for: {file_name}")

def main():
    if not os.path.exists(SOURCE_DIR):
        print(f"Error: SOURCE_DIR '{SOURCE_DIR}' not found.")
        return
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        process_file(file_name)

if __name__ == '__main__':
    main()
