import os
import json
import glob

def parse_source_file(file_path):
    domains = []
    domain_suffixes = []
    ip_cidrs = []
    raw_rules = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            raw_rules.append(line)
            
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 2:
                rule_type = parts[0].upper()
                rule_value = parts[1]
                if rule_type == 'DOMAIN-SUFFIX':
                    domain_suffixes.append(rule_value)
                elif rule_type == 'DOMAIN':
                    domains.append(rule_value)
                elif rule_type in ['IP-CIDR', 'IP-CIDR6']:
                    ip_cidrs.append(rule_value)
            else:
                domain_suffixes.append(line)
    return {
        'domains': domains,
        'domain_suffixes': domain_suffixes,
        'ip_cidrs': ip_cidrs,
        'raw_rules': raw_rules
    }

def main():
    os.makedirs('clash', exist_ok=True)
    os.makedirs('shadowrocket', exist_ok=True)
    os.makedirs('quantumultx', exist_ok=True)
    os.makedirs('pac', exist_ok=True)
    os.makedirs('singbox', exist_ok=True)

    txt_files = glob.glob('source/*.txt')
    for txt_path in txt_files:
        file_name = os.path.basename(txt_path)
        base_name = os.path.splitext(file_name)[0]
        file_keyword = base_name.lower()
        
        data = parse_source_file(txt_path)
        
        # 1. Clash Classical YAML
        with open(f'clash/{base_name}.yaml', 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for r in data['raw_rules']:
                f.write(f"  - '{r}'\n")
                
        # 2. Shadowrocket List
        with open(f'shadowrocket/{base_name}.list', 'w', encoding='utf-8') as f:
            for r in data['raw_rules']:
                f.write(f"{r}\n")
                
        # 3. Quantumult X Snippet
        with open(f'quantumultx/{base_name}.snippet', 'w', encoding='utf-8') as f:
            for r in data['raw_rules']:
                parts = [p.strip() for p in r.split(',')]
                if len(parts) >= 2:
                    rtype = parts[0].upper()
                    rval = parts[1]
                    if rtype == 'DOMAIN-SUFFIX':
                        f.write(f"HOST-SUFFIX, {rval}, proxy\n")
                    elif rtype == 'DOMAIN':
                        f.write(f"HOST, {rval}, proxy\n")
                    elif rtype == 'DOMAIN-KEYWORD':
                        f.write(f"HOST-KEYWORD, {rval}, proxy\n")
                    elif rtype in ['IP-CIDR', 'IP-CIDR6']:
                        f.write(f"{rtype}, {rval}, proxy\n")
                    else:
                        f.write(f"{r}\n")
                else:
                    f.write(f"HOST-SUFFIX, {r}, proxy\n")
                    
        # 4. PAC File
        with open(f'pac/{base_name}.pac', 'w', encoding='utf-8') as f:
            f.write("function FindProxyForURL(url, host) {\n")
            for d in data['domains']:
                f.write(f"    if (host === '{d}') return 'PROXY 127.0.0.1:7890; DIRECT';\n")
            for s in data['domain_suffixes']:
                f.write(f"    if (dnsDomainIs(host, '.{s}') || host === '{s}') return 'PROXY 127.0.0.1:7890; DIRECT';\n")
            f.write("    return 'DIRECT';\n")
            f.write("}\n")
            
        # Binary Ruleset Intelligent Routing Filter
        if 'classic' in file_keyword:
            print(f"Skipping binary conversion for classic file: {file_name}")
            continue
            
        elif 'ip' in file_keyword:
            if data['ip_cidrs']:
                with open(f'clash/tmp_{base_name}_ipcidr.yaml', 'w', encoding='utf-8') as f:
                    f.write("payload:\n")
                    for ip in data['ip_cidrs']:
                        f.write(f"  - '{ip}'\n")
                sb_json = {"version": 1, "rules": [{"ip_cidr": data['ip_cidrs']}]}
                with open(f'singbox/tmp_{base_name}.json', 'w', encoding='utf-8') as f:
                    json.dump(sb_json, f, indent=2)
                    
        else:
            if data['domains'] or data['domain_suffixes']:
                with open(f'clash/tmp_{base_name}_domain.yaml', 'w', encoding='utf-8') as f:
                    f.write("payload:\n")
                    for d in data['domains']:
                        f.write(f"  - '{d}'\n")
                    for s in data['domain_suffixes']:
                        f.write(f"  - '+.{s}'\n")
                sb_rules = {}
                if data['domains']:
                    sb_rules["domain"] = data['domains']
                if data['domain_suffixes']:
                    sb_rules["domain_suffix"] = data['domain_suffixes']
                sb_json = {"version": 1, "rules": [sb_rules]}
                with open(f'singbox/tmp_{base_name}.json', 'w', encoding='utf-8') as f:
                    json.dump(sb_json, f, indent=2)

if __name__ == '__main__':
    main()
