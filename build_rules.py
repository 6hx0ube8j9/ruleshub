import os
import sys  # 导入 sys 用于控制退出码

# 定义目录路径
RULES_DIR = "rules"
CLASH_DIR = "clash"

# 确保输出目录存在
os.makedirs(CLASH_DIR, exist_ok=True)

def clean_and_parse_line(line):
    line = line.strip()
    
    # 【原则 1】：保持现有的注释过滤逻辑不变！
    if not line or line.startswith('#') or line.startswith('//') or line.startswith(';'):
        return None, None
        
    if line.startswith('-'):
        line = line.lstrip('-').strip()
    line = line.replace("'", "").replace('"', "")

    # 【原则 3】：保持向前兼容
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

    if '/' in line and any(c.isdigit() for c in line):
        return 'ip6' if ':' in line else 'ip', line

    # 【修改要求 1 & 2】：前导点处理，彻底删掉 count('.')
    if line.startswith('.'):
        return 'suffix', line.lstrip('.').lower()

    return 'suffix', line.lstrip('.').lower()

def process_file(file_path, base_name):
    rules = {
        'suffix': set(), 'full': set(), 'keyword': set(),
        'ip': set(), 'ip6': set(), 'process': set(), 'useragent': set()
    }
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            rtype, val = clean_and_parse_line(line)
            if rtype and val:
                rules[rtype].add(val)

    # 打印单文件解析日志，方便在 GitHub Actions 中对账
    total_domains = len(rules['suffix']) + len(rules['full'])
    total_ips = len(rules['ip']) + len(rules['ip6'])
    print(f"   ➔ 解析成功: 域名类 {total_domains} 条, IP类 {total_ips} 条")

    # 1. 生成标准的 Clash Classical 混合规则格式 YAML 文件
    classical_file = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(classical_file, 'w', encoding='utf-8') as f:
        f.write("payload:\n")
        for r_type in ['suffix', 'full', 'keyword', 'ip', 'ip6', 'process', 'useragent']:
            prefix = {
                'suffix': 'DOMAIN-SUFFIX', 'full': 'DOMAIN', 'keyword': 'DOMAIN-KEYWORD',
                'ip': 'IP-CIDR', 'ip6': 'IP-CIDR6', 'process': 'PROCESS-NAME', 'useragent': 'USER-AGENT'
            }[r_type]
            for val in sorted(rules[r_type]):
                f.write(f"  - '{prefix},{val}'\n")

    # 2. 为 Mihomo MRS 编译准备纯粹的临时 Domain YAML 文件
    clash_domains = [f"+.{val}" for val in sorted(rules['suffix'])] + sorted(list(rules['full']))
    if clash_domains:
        domain_tmp_file = os.path.join(CLASH_DIR, f"tmp_{base_name}_domain.yaml")
        with open(domain_tmp_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for item in clash_domains:
                f.write(f"  - '{item}'\n")

    # 3. 为 Mihomo MRS 编译准备纯粹的临时 IP-CIDR YAML 文件
    clash_ips = sorted(list(rules['ip']) + list(rules['ip6']))
    if clash_ips:
        ip_tmp_file = os.path.join(CLASH_DIR, f"tmp_{base_name}_ipcidr.yaml")
        with open(ip_tmp_file, 'w', encoding='utf-8') as f:
            f.write("payload:\n")
            for item in clash_ips:
                f.write(f"  - '{item}'\n")

def main():
    # 【防御机制 1】：如果找不到目录，直接终止 Action 并报错，防止静默通过
    if not os.path.exists(RULES_DIR):
        print(f"❌ 错误: 未找到规则源目录 '{RULES_DIR}'！")
        print("请检查项目根目录下是否存在该文件夹，并注意 Linux 环境下严格区分大小写（例如 rules vs Rules）。")
        sys.exit(1)
        
    file_count = 0
    for file_name in os.listdir(RULES_DIR):
        file_path = os.path.join(RULES_DIR, file_name)
        if os.path.isfile(file_path) and not file_name.startswith('.'):
            base_name = os.path.splitext(file_name)[0]
            print(f"📂 正在处理规则源文件: {file_name} -> {base_name}")
            process_file(file_path, base_name)
            file_count += 1

    # 【防御机制 2】：如果有效文件数为 0，直接终止 Action 报错
    if file_count == 0:
        print(f"❌ 错误: 在 '{RULES_DIR}' 目录中没有找到任何有效的规则源文件！")
        sys.exit(1)

if __name__ == "__main__":
    main()
