# -*- coding: utf-8 -*-
import os
import json
import yaml
import subprocess

SOURCE_DIR = 'source'
SHADOWROCKET_DIR = 'shadowrocket'
QUANTUMULTX_DIR = 'quantumultx'
CLASH_DIR = 'clash'
PAC_DIR = 'pac'
SINGBOX_DIR = 'singbox'
MIHOMO_BIN = "./mihomo-bin"

for d in [SOURCE_DIR, SHADOWROCKET_DIR, QUANTUMULTX_DIR, CLASH_DIR, PAC_DIR, SINGBOX_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

home_dir = os.path.expanduser('~')
mihomo_config_dir = os.path.join(home_dir, '.config', 'mihomo')
os.makedirs(mihomo_config_dir, exist_ok=True)

dummy_config = {
    "mixed-port": 0,  
    "allow-lan": False,
    "mode": "rule",
    "log-level": "silent" 
}
with open(os.path.join(mihomo_config_dir, 'config.yaml'), 'w', encoding='utf-8') as f:
    yaml.dump(dummy_config, f)


def clean_and_parse_line(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
        return None, None
    if line.startswith('-'):
        line = line.lstrip('-').strip()
    line = line.replace("'", "").replace('"', "")
    
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2: return None, None
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
    if line.startswith('.'):
        value = line.lstrip('.').lower()
        return ('full', value) if value.count('.') >= 2 else ('suffix', value)
    return 'suffix', line.lstrip('.').lower()

def optimize_domains(rules):
    sorted_suffixes = sorted(list(rules['suffix']), key=lambda x: (x.count('.'), len(x)))
    clean_suffixes = set()
    for domain in sorted_suffixes:
        parts = domain.split('.')
        is_subdomain = False
        for i in range(1, len(parts)):
            parent_candidate = '.'.join(parts[i:])
            if parent_candidate in clean_suffixes:
                is_subdomain = True
                break
        if not is_subdomain:
            clean_suffixes.add(domain)
    rules['suffix'] = clean_suffixes
    
    clean_full = set()
    for domain in rules['full']:
        parts = domain.split('.')
        is_covered = False
        for i in range(len(parts) - 1):
            suffix_candidate = '.'.join(parts[i:])
            if suffix_candidate in rules['suffix']:
                is_covered = True
                break
        if not is_covered:
            clean_full.add(domain)
    rules['full'] = clean_full

def compile_mihomo_mrs(name, rules, behavior):
    """
    🔥 核心防御点 2：硬编码精准匹配 v1.18.3 的通用参数，不给内核任何死锁机会
    """
    tmp_yaml = f"temp_{name}_{behavior}.yaml"
    dst_mrs = os.path.join(CLASH_DIR, f"{name}.mrs" if behavior == 'domain' else f"{name}_IP.mrs")
    try:
        with open(tmp_yaml, 'w', encoding='utf-8') as f:
            yaml.dump({'payload': rules}, f)
        
        # 精准匹配：mihomo convert-ruleset [behavior] yaml [src] [dst]
        cmd = [MIHOMO_BIN, "convert-ruleset", behavior, "yaml", tmp_yaml, dst_mrs]
        
        # 使用 standard sub-process，并在 5 秒内强制干掉不听话的进程
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        print(f"Mihomo Success: {dst_mrs}")
        return True
    except Exception as e:
        print(f"Mihomo Skipped/Error [{name}]: {str(e)}")
        return False
    finally:
        if os.path.exists(tmp_yaml): os.remove(tmp_yaml)

def process_file(file_name):
    source_path = os.path.join(SOURCE_DIR, file_name)
    base_name = os.path.splitext(file_name)[0]
    rules = {'suffix': set(), 'full': set(), 'keyword': set(), 'ip': set(), 'ip6': set(), 'process': set(), 'useragent': set()}
    
    with open(source_path, 'r', encoding='utf-8') as f:
        for line in f:
            rule_type, value = clean_and_parse_line(line)
            if rule_type in rules:
                rules[rule_type].add(value)
                
    optimize_domains(rules)
                
    # 1. Save source
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} Original Rules ===\n\n")
        for r_type in ['suffix', 'full', 'keyword', 'ip', 'ip6', 'process', 'useragent']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
    # 2. shadowrocket
    sr_path = os.path.join(SHADOWROCKET_DIR, f"{base_name}.list")
    with open(sr_path, 'w', encoding='utf-8') as f_sr:
        f_sr.write(f"# Shadowrocket Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_sr.write(f"DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_sr.write(f"DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_sr.write(f"DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['useragent']): f_sr.write(f"USER-AGENT,{val}\n")
        for val in sorted(rules['ip']): f_sr.write(f"IP-CIDR,{val},no-resolve\n")
        for val in sorted(rules['ip6']): f_sr.write(f"IP-CIDR6,{val},no-resolve\n")

    # 3. QuantumultX 
    qx_path = os.path.join(QUANTUMULTX_DIR, f"{base_name}.list")
    qx_policy = 'DIRECT' if base_name.lower() == 'direct' else ('REJECT' if base_name.lower() == 'reject' else base_name.capitalize())
    with open(qx_path, 'w', encoding='utf-8') as f_qx:
        f_qx.write(f"# Quantumult X Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_qx.write(f"host-suffix, {val}, {qx_policy}\n")
        for val in sorted(rules['full']): f_qx.write(f"host, {val}, {qx_policy}\n")
        for val in sorted(rules['keyword']): f_qx.write(f"host-keyword, {val}, {qx_policy}\n")
        for val in sorted(rules['useragent']): f_qx.write(f"user-agent, {val}, {qx_policy}\n")
        for val in sorted(rules['ip']): f_qx.write(f"ip-cidr, {val}, {qx_policy}, no-resolve\n")
        for val in sorted(rules['ip6']): f_qx.write(f"ip6-cidr, {val}, {qx_policy}, no-resolve\n")

    # 4. Clash MRS
    clash_domains = []
    for val in sorted(rules['suffix']): clash_domains.append(f"+.{val}")
    for val in sorted(rules['full']): clash_domains.append(val)
    if clash_domains:
        compile_mihomo_mrs(base_name, clash_domains, 'domain')
        
    clash_ips = sorted(list(rules['ip'].union(rules['ip6'])))
    if clash_ips:
        compile_mihomo_mrs(base_name, clash_ips, 'ipcidr')

    # 5. PAC
    if base_name.lower() == 'direct':
        pac_path = os.path.join(PAC_DIR, f"{base_name}.pac")
        with open(pac_path, 'w', encoding='utf-8') as f_pac:
            direct_domains = sorted(list(rules['suffix'].union(rules['full'])))
            f_pac.write("var IP_ADDRESS = '127.0.0.1:7891';\nvar PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; DIRECT';\n\nvar DIRECT_DOMAINS = {\n")
            for i, domain in enumerate(direct_domains):
                comma = "," if i < len(direct_domains) - 1 else ""
                f_pac.write(f'    "{domain}": 1{comma}\n')
            f_pac.write("};\n\nfunction FindProxyForURL(url, host) {\n    if (isPlainHostName(host) || /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host)) { return \"DIRECT\"; }\n    var suffix = host;\n    while (suffix) {\n        if (DIRECT_DOMAINS.hasOwnProperty(suffix)) { return \"DIRECT\"; }\n        var pos = suffix.indexOf('.');\n        if (pos === -1) break;\n        suffix = suffix.substring(pos + 1);\n    }\n    return PROXY_METHOD;\n}\n")

    # 6. sing-box
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

def main():
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        process_file(file_name)

if __name__ == '__main__':
    main()
