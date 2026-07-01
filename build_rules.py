import os

# 定义目录路径
RULES_DIR = "rules"
CLASH_DIR = "clash"

# 确保输出目录存在
os.makedirs(CLASH_DIR, exist_ok=True)

def clean_and_parse_line(line):
    line = line.strip()
    
    # 【原则 1】：保持现有的注释过滤逻辑不变！
    # 凡是以 #、//、; 开头的行，100% 属于注释，必须直接忽略（返回 None, None）
    if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
        return None, None
        
    # 保持现有的其他前置清洗逻辑（兼容原版处理破折号、引号等）
    if line.startswith('-'):
        line = line.lstrip('-').strip()
    line = line.replace("'", "").replace('"', "")

    # 【原则 3】：保持向前兼容，处理带逗号的整行规则 DOMAIN-SUFFIX/IP-CIDR 等
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 2:
            return None, None
        p1 = parts[0].upper()
        p2 = parts[1]
        if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']:
            return 'suffix', p2.lstrip('.').lower()
        if p1 in ['DOMAIN', 'HOST', 'FULL']:
            return 'full', p2.lower()
        if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']:
            return 'keyword', p2.lower()
        if p1 in ['IP-CIDR', 'IP']:
            return 'ip', p2
        if p1 in ['IP-CIDR6', 'IP6-CIDR', 'IP6']:
            return 'ip6', p2
        if p1 in ['PROCESS-NAME', 'PROCESS']:
            return 'process', p2
        if p1 in ['USER-AGENT', 'USERAGENT']:
            return 'useragent', p2
        return None, None

    # 保持向前兼容：处理纯 IP 带掩码情况
    if '/' in line and any(c.isdigit() for c in line):
        return 'ip6' if ':' in line else 'ip', line

    # 【修改要求 1 & 2】：只要文本是以 . 开头，一律剥离首位的 . 并直接归类为 'suffix'
    # 彻底删掉了通过计算点的数量（value.count('.') >= 2）来划分 'full' 的死板逻辑！
    if line.startswith('.'):
        return 'suffix', line.lstrip('.').lower()

    # 保持向前兼容：处理无标签纯域名等（原逻辑直接归为 suffix）
    return 'suffix', line.lstrip('.').lower()

def process_file(file_path, base_name):
    # 初始化分类规则集合以自动去重
    rules = {
        'suffix': set(),
        'full': set(),
        'keyword': set(),
        'ip': set(),
        'ip6': set(),
        'process': set(),
        'useragent': set()
    }
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            rtype, val = clean_and_parse_line(line)
            if rtype and val:
                rules[rtype].add(val)

    # 1. 生成标准的 Clash Classical 混合规则格式 YAML 文件（保持完全向后兼容）
    classical_file = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(classical_file, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for val in sorted(rules['suffix']):
            f.write(f"  - 'DOMAIN-SUFFIX,{val}'\n")
        for val in sorted(rules['full']):
            f.write(f"  - 'DOMAIN,{val}'\n")
        for val in sorted(rules['keyword']):
            f.write(f"  - 'DOMAIN-KEYWORD,{val}'\n")
        for val in sorted(rules['ip']):
            f.write(f"  - 'IP-CIDR,{val}'\n")
        for val in sorted(rules['ip6']):
            f.write(f"  - 'IP-CIDR6,{val}'\n")
        for val in sorted(rules['process']):
            f.write(f"  - 'PROCESS-NAME,{val}'\n")
        for val in sorted(rules['useragent']):
            f.write(f"  - 'USER-AGENT,{val}'\n")

    # 2. 为 Mihomo MRS 编译准备纯粹的临时 Domain YAML 文件 (behavior: domain)
    # 包含 suffix (使用 Mihomo 标准的 +. 前缀表示) 和 full 匹配
    clash_domains = []
    for val in sorted(rules['suffix']):
        clash_domains.append(f"+.{val}")
    for val in sorted(rules['full']):
        clash_domains.append(val)
        
    if clash_domains:
        domain_tmp_file = os.path.join(CLASH_DIR, f"tmp_{base_name}_domain.yaml")
        with open(domain_tmp_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for item in clash_domains:
                f.write(f"  - '{item}'\n")

    # 3. 为 Mihomo MRS 编译准备纯粹的临时 IP-CIDR YAML 文件 (behavior: ipcidr)
    clash_ips = sorted(list(rules['ip']) + list(rules['ip6']))
    if clash_ips:
        ip_tmp_file = os.path.join(CLASH_DIR, f"tmp_{base_name}_ipcidr.yaml")
        with open(ip_tmp_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for item in clash_ips:
                f.write(f"  - '{item}'\n")

def main():
    if not os.path.exists(RULES_DIR):
        print(f"错误: 未找到规则源目录 '{RULES_DIR}'")
        return
        
    for file_name in os.listdir(RULES_DIR):
        file_path = os.path.join(RULES_DIR, file_name)
        if os.path.isfile(file_path) and not file_name.startswith('.'):
            base_name = os.path.splitext(file_name)[0]
            print(f"正在处理规则源文件: {file_name} -> {base_name}")
            process_file(file_path, base_name)

if __name__ == "__main__":
    main()
