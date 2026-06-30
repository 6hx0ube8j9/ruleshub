# -*- coding: utf-8 -*-
import os

# 定义工作目录（这次加上了 clash）
SOURCE_DIR = 'source'
SHADOWROCKET_DIR = 'shadowrocket'
QUANTUMULTX_DIR = 'quantumultx'
CLASH_DIR = 'clash'

# 确保所有目录存在
for d in [SOURCE_DIR, SHADOWROCKET_DIR, QUANTUMULTX_DIR, CLASH_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

def clean_and_parse_line(line):
    """
    终极语法绞肉机：
    输入无论是 Clash / 小火箭 / 圈X / 青龙，全部绞碎，精准提纯为底稿格式。
    返回: (rule_type, value) 或 (None, None)
    """
    line = line.strip()
    
    # 1. 过滤空行和各种软件的注释行 (#, //, ;, -)
    if not line or line.startswith('#') or line.startswith('//') or line.startswith(';') or line.startswith('//'):
        return None, None
        
    # 2. 绞碎 Clash 格式 (例如: - DOMAIN-SUFFIX,apple.com,DIRECT 或 - 'DOMAIN,apple.com')
    if line.startswith('-'):
        line = line.lstrip('-').strip()
        line = line.replace("'", "").replace('"', "") # 剥离 YAML 的引号
        
    # 3. 统一将所有软件的“逗号分隔符”切开，拿掉所有的策略尾巴（DIRECT, PROXY, no-resolve 等）
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        p1 = parts[0].upper()
        p2 = parts[1]
        
        # 兼容小火箭 / 圈X / Clash 的前缀
        if p1 in ['DOMAIN-SUFFIX', 'HOST-SUFFIX', 'SUFFIX']:
            return 'suffix', p2.lstrip('.')
        if p1 in ['DOMAIN', 'HOST', 'FULL']:
            return 'full', p2
        if p1 in ['DOMAIN-KEYWORD', 'HOST-KEYWORD', 'KEYWORD']:
            return 'keyword', p2
        if p1 in ['IP-CIDR', 'IP-CIDR6', 'IP']:
            return 'ip', p2
            
        # 如果是手打的标准底稿格式 (例如: suffix,apple.com)
        if p1.lower() in ['suffix', 'full', 'keyword', 'ip']:
            val = p2.lstrip('.') if p1.lower() in ['suffix', 'full'] else p2
            return p1.lower(), val

    # 4. 绞碎青龙带点格式 (例如: .apple.com)
    if line.startswith('.'):
        value = line.lstrip('.')
        return ('full', value) if value.count('.') >= 2 else ('suffix', value)
            
    # 5. 绞碎纯 IP 段 (含有斜杠 / 且包含数字)
    if '/' in line and any(c.isdigit() for c in line):
        return 'ip', line

    # 6. 兜底：无任何特征的普通域名字符串，默认直击根域名后缀
    return 'suffix', line.lstrip('.')

def process_file(file_name):
    source_path = os.path.join(SOURCE_DIR, file_name)
    base_name = os.path.splitext(file_name)[0]
    
    # 容器去重
    rules = {'suffix': set(), 'full': set(), 'keyword': set(), 'ip': set()}
    
    # 【进料】读取并用绞肉机粉碎提纯
    with open(source_path, 'r', encoding='utf-8') as f:
        for line in f:
            rule_type, value = clean_and_parse_line(line)
            if rule_type in rules:
                rules[rule_type].add(value)
                
    # 【出料 1】强制清洗并格式化底稿，确保底稿只留下神圣的“标准格式”
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {base_name.upper()} 原始底稿 (自动规范化排版) ===\n")
        f_source.write("# 规范格式：类型,内容 (例如 suffix,apple.com)\n\n")
        
        for r_type in ['suffix', 'full', 'keyword', 'ip']:
            if rules[r_type]:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
    # 【出料 2】衍生派生：小火箭专属目录 (.list)
    sr_path = os.path.join(SHADOWROCKET_DIR, f"{base_name}.list")
    with open(sr_path, 'w', encoding='utf-8') as f_sr:
        f_sr.write(f"# Shadowrocket Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_sr.write(f"DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_sr.write(f"DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_sr.write(f"DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['ip']): f_sr.write(f"IP-CIDR,{val},no-resolve\n")

    # 【出料 3】衍生派生：圈X专属目录 (.list)
    qx_path = os.path.join(QUANTUMULTX_DIR, f"{base_name}.list")
    with open(qx_path, 'w', encoding='utf-8') as f_qx:
        f_qx.write(f"# Quantumult X Rule-Set: {base_name}\n\n")
        for val in sorted(rules['suffix']): f_qx.write(f"HOST-SUFFIX,{val},DIRECT\n")
        for val in sorted(rules['full']): f_qx.write(f"HOST,{val},DIRECT\n")
        for val in sorted(rules['keyword']): f_qx.write(f"HOST-KEYWORD,{val},DIRECT\n")
        for val in sorted(rules['ip']): f_qx.write(f"IP-CIDR,{val},DIRECT\n")

    # 🌟【新增强调：出料 4】衍生派生：Clash 专属目录 (.yaml)
    clash_path = os.path.join(CLASH_DIR, f"{base_name}.yaml")
    with open(clash_path, 'w', encoding='utf-8') as f_clash:
        f_clash.write(f"# Clash Payload Rule-Set: {base_name}\n")
        f_clash.write("payload:\n")  # 标准的 Clash 规则集开头
        for val in sorted(rules['suffix']): f_clash.write(f"  - DOMAIN-SUFFIX,{val}\n")
        for val in sorted(rules['full']): f_clash.write(f"  - DOMAIN,{val}\n")
        for val in sorted(rules['keyword']): f_clash.write(f"  - DOMAIN-KEYWORD,{val}\n")
        for val in sorted(rules['ip']): f_clash.write(f"  - IP-CIDR,{val},no-resolve\n")

    print(f"✅ 绞肉机运行成功: {file_name} 已提纯并派生（包含 Clash）完毕。")

def main():
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith('.txt')]
    for file_name in files:
        process_file(file_name)

if __name__ == '__main__':
    main()
