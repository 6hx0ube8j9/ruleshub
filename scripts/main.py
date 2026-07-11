# -*- coding: utf-8 -*-
import os
import json
import re
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# 导入配套自定义模块
import rules_processor
import rules_formatter

# ==========================================
# 1. 基础物理路径与工具链定义
# ==========================================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__)) # /project/scripts
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                 # /project

# 规则输出根目录与子目录
RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR       = os.path.join(RULESET_BASE_DIR, 'source')
MIHOMO_DIR       = os.path.join(RULESET_BASE_DIR, 'mihomo')

# 二进制工具链与配置文件路径（存放于 /scripts 目录）
RULESET_JSON_PATH = os.path.join(SCRIPT_DIR, 'ruleset.json')
MIHOMO_BIN        = os.path.join(SCRIPT_DIR, 'mihomo-bin')
SINGBOX_BIN       = os.path.join(SCRIPT_DIR, 'sing-box')

# ==========================================
# 2. 平台分发与编译矩阵配置
# ==========================================
GLOBAL_PLATFORM_MATRIX = {
    'loon':             {'field': 'loon',             'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
    'mihomo_classical': {'field': 'mhm_classical',    'dir': os.path.join(MIHOMO_DIR, 'classical')},    
    'quantumultx':      {'field': 'qx', 'policy_cfg': 'qx_policy', 'dir': os.path.join(RULESET_BASE_DIR, 'quantumultx')},    
    'singbox':          {'field': 'singbox',          'dir': os.path.join(RULESET_BASE_DIR, 'singbox')},
    'shadowrocket':     {'field': 'sr',               'dir': os.path.join(RULESET_BASE_DIR, 'shadowrocket')},    
    'pac':              {'field': 'pac', 'whitelist': ['direct', 'china'], 'dir': os.path.join(RULESET_BASE_DIR, 'pac')}
}

MIHOMO_MRS_TUNNEL_MATRIX = {
    'mihomo_ipcidr': {
        'field': 'mhm_ipcidr',                                    
        'regex': r'(^|[_0-9-])ip([_0-9-]|$)',         
    },
    'mihomo_domain': {
        'field': 'mhm_domain',
        'regex': r'^(?!.*(^|[_0-9-])ip([_0-9-]|$)).*$',
        'blacklist': ['classic', 'nodomain']
    }
}

# ==========================================
# 3. 运行环境自举（自动创建目录与配置文件）
# ==========================================
# 初始化基础静态目录集合
REQUIRED_DIRS = {
    SCRIPT_DIR,
    RULESET_BASE_DIR, 
    SOURCE_DIR, 
    MIHOMO_DIR,
    os.path.join(MIHOMO_DIR, 'domain'),
    os.path.join(MIHOMO_DIR, 'ipcidr')
}

# 动态合并配置矩阵中的所有平台输出目录
REQUIRED_DIRS.update(plat_cfg['dir'] for plat_cfg in GLOBAL_PLATFORM_MATRIX.values() if 'dir' in plat_cfg)

# 统一创建所有缺失的物理目录
for d in sorted(REQUIRED_DIRS):
    os.makedirs(d, exist_ok=True)

# 确保默认的 ruleset.json 文件存在
if not os.path.exists(RULESET_JSON_PATH):
    with open(RULESET_JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump([], f, indent=2, ensure_ascii=False)

# 加载并解析配置文件
try:
    with open(RULESET_JSON_PATH, 'r', encoding='utf-8') as f:
        FILE_POLICY_ROUTER = json.load(f)
except json.JSONDecodeError as e:
    print(f"\n❌ ruleset.json [{e.lineno}:{e.colno}] -> {e.msg}\n")
    import sys
    sys.exit(1) 

# ==========================================
# 4. 基础工具函数集
# ==========================================
def is_truthy_cfg(policy, key):
    """判断配置项是否为真值"""
    val = policy.get(key)
    return val is True or str(val).lower() == 'true'
    
def parse_target_config(policy, field_name, default_base_name):
    """解析目标平台的启用状态与输出别名"""
    val = policy.get(field_name)
    if val is False or str(val).lower() == 'false':
        return False, None
    if val is None or val == '' or val is True or str(val).lower() == 'true':
        return True, default_base_name
    return True, str(val).strip()
    
def get_smart_base_name(name, policy, existing_names):
    """基于规则名称或URL动态提取并生成唯一的合法文件名"""
    if name.strip():
        base = name.strip().lower() 
    else:
        url = policy.get('url', '')
        first_url = url[0] if isinstance(url, list) and url else url
        base = 'untitled_unknown'
        if first_url:
            try:
                last_part = first_url.split('/')[-1]
                extracted = os.path.splitext(last_part)[0]
                if extracted.strip():
                    base = extracted.strip().lower() 
            except Exception:
                pass
                
    orig_base = base
    counter = 1
    while base in existing_names:
        base = f"{orig_base}_{counter}"
        counter += 1
    return base

# ==========================================
# 5. 数据流加载、合并与过滤核心区
# ==========================================
def load_local_raw_lines(source_path):
    """【纯IO】读取本地缓存的原始规则文本行，不参与任何解析"""
    if not os.path.exists(source_path):
        return []
        
    with open(source_path, 'r', encoding='utf-8') as f_local:
        return f_local.readlines() 


def load_remote_raw_lines_batch(url_cfg):
    """【纯IO】多线程批量并发拉取远程原始规则流，不参与任何解析"""
    url_list = url_cfg if isinstance(url_cfg, list) else ([url_cfg] if url_cfg else [])
    if not url_list:
        return []

    all_raw_lines = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_single_url, url): url for url in url_list}
        for future in as_completed(future_to_url):
            _, lines = future.result()
            all_raw_lines.extend(lines)
            
    return all_raw_lines  

def fetch_single_url(remote_url):
    """执行单条网络请求获取远程文件内容"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(remote_url, headers=headers, timeout=15)
        if response.status_code == 200:
            content = response.content.decode('utf-8', errors='ignore')
            return remote_url, content.splitlines()
        print(f"Warning: {remote_url} returned status {response.status_code}")
        return remote_url, []
    except requests.exceptions.RequestException as e:
        print(f"Warning: Network error fetching {remote_url} - {e}")
        return remote_url, []
    except Exception as e:
        print(f"Warning: Unexpected error fetching {remote_url} - {e}")
        return remote_url, []

def fetch_and_merge_rules(base_name, policy):
    """汇总、去重并持久化本地与远程规则集"""
    source_enable, _ = parse_target_config(policy, 'source', base_name)
    source_file_name = base_name.lower()
    source_path = os.path.join(SOURCE_DIR, f"{source_file_name}.txt")
    
    # 1. 搬运工干活：只拿原材料（纯文本行列表）
    local_raw = load_local_raw_lines(source_path)
    remote_raw = load_remote_raw_lines_batch(policy.get('url', []))
    
    # 2. 扔给黑盒子：一键送入处理器的大管道（解析、合并、主权过滤、域名优化全在里面闭环）
    rules = rules_processor.execute_rules_pipeline(local_raw, remote_raw)
    
    # 3. 搬运工干活：把完美的成品落盘
    save_local_rules(source_path, source_file_name, rules, rules_processor.source_keys, source_enable)
    
    return rules

def save_local_rules(source_path, source_file_name, rules, rule_keys, source_enable):
    """保存合并加工后的规则到本地 source 目录"""
    if not source_enable or not any(len(rules[k]) > 0 for k in rule_keys):
        return

    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {source_file_name} Combined Base Rules ===\n\n")
        for r_type in rule_keys:
            if rules.get(r_type):
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")

def dispatch_rules_to_targets(base_name, policy, rules, global_matrix):
    """将内存中的规则分流到各平台对应的全局矩阵结构中"""
    for plat, config in GLOBAL_PLATFORM_MATRIX.items():
        field_name = config['field']
        enabled, target_name = parse_target_config(policy, field_name, base_name)
        if not enabled:
            continue

        if plat == 'quantumultx':
            policy_cfg_field = config.get('policy_cfg', 'qx_policy')
            qx_policy_label = policy.get(policy_cfg_field, base_name.capitalize() if base_name.lower() not in ['direct', 'reject'] else base_name.lower())
            
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = {
                    'policy_label': qx_policy_label,
                    **{k: set() for k in rules.keys()}
                }
            for k in rules:
                if k in global_matrix[plat][target_name]:
                    global_matrix[plat][target_name][k].update(rules[k])
                    
        elif plat == 'pac':
            pac_val = policy.get('pac')
            pac_en, pac_name = False, None
            
            if pac_val is True or str(pac_val).lower() == 'true' or base_name.lower() in config.get('whitelist', []):
                pac_en, pac_name = True, base_name
            elif isinstance(pac_val, str) and pac_val.strip() and str(pac_val).lower() != 'false':
                pac_en, pac_name = True, pac_val.strip()

            if pac_en:
                if pac_name not in global_matrix[plat]:
                    global_matrix[plat][pac_name] = set()
                global_matrix[plat][pac_name].update(rules.get('suffix', set()))
                global_matrix[plat][pac_name].update(rules.get('full', set()))
                
        else:
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = {k: set() for k in rules.keys()}
            for k, v in rules.items():
                global_matrix[plat][target_name][k].update(v)

def normalize_and_discover_local_sources(router_cleaned):
    """自动扫描并导入本地新放入的txt独立规则文件"""
    if not os.path.exists(SOURCE_DIR): 
        return
        
    for f in os.listdir(SOURCE_DIR):
        if f.endswith('.txt'):
            if not f.islower():
                old_path = os.path.join(SOURCE_DIR, f)
                new_f = f.lower()
                new_path = os.path.join(SOURCE_DIR, new_f)
                
                if os.path.exists(new_path):
                    try:
                        with open(old_path, 'r', encoding='utf-8') as f_old:
                            old_content = f_old.read()
                        with open(new_path, 'a', encoding='utf-8') as f_new:
                            f_new.write("\n" + old_content)
                        os.remove(old_path)
                    except Exception as e:
                        print(f"⚠️ [WARN] Failed to merge local source '{f}': {e}")
                else:
                    try: 
                        os.rename(old_path, new_path)
                    except Exception as e: 
                        print(f"⚠️ [WARN] Failed to rename local source '{f}': {e}")
                f = new_f

            local_base_name = os.path.splitext(f)[0]
            if local_base_name in router_cleaned: 
                continue
            router_cleaned[local_base_name] = {'name': local_base_name, 'url': []}

def compile_mihomo_mrs(base_name, policy, rules):
    """将 YAML 规则集过滤、清洗并编译为 Mihomo 二进制 .mrs 格式"""
    if not os.path.exists(MIHOMO_BIN):
        print(f"❌ Error: '{MIHOMO_BIN}' not found.")
        return

    name_lower = base_name.lower()
    
    for tunnel_type, config in MIHOMO_MRS_TUNNEL_MATRIX.items():
        # 1. 策略与黑名单拦截 (紧凑门禁)
        if any(b in name_lower for b in config.get('blacklist', [])): continue
        if 'regex' in config and not re.search(config['regex'], name_lower): continue
        if not is_truthy_cfg(policy, config['field']): continue

        # 2. 动态路由派发 (干掉 if/elif 核心)
        sub_dir = tunnel_type.split('_')[1]
        formatter = getattr(rules_formatter, f"generate_{tunnel_type}", None)
        content = formatter(rules) if formatter else ""
        if not content: continue

        # 3. 执行落盘与编译
        yaml_path = os.path.join(MIHOMO_DIR, sub_dir, f"{name_lower}.yaml")
        mrs_out_path = os.path.join(MIHOMO_DIR, sub_dir, f"{name_lower}.mrs")
        
        try:
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(content)
            subprocess.run([MIHOMO_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], check=True)
            print(f"Successfully compiled Mihomo {sub_dir.upper()}: {name_lower}.mrs")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error: Failed to compile {name_lower} ({sub_dir}): {e}")

def compile_singbox_srs(global_matrix, singbox_dir):
    """调用 sing-box 二进制工具链将 JSON 编译为二进制 .srs 规则集"""
    if not os.path.exists(SINGBOX_BIN) or not global_matrix.get('singbox'): 
        return

    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path = os.path.join(singbox_dir, f"{g_name}.json")
        sb_srs_path = os.path.join(singbox_dir, f"{g_name}.srs")

        if not os.path.exists(sb_path): continue        
        if not any(raw_rules.values()):
            continue

        try:
            subprocess.run([SINGBOX_BIN, 'rule-set', 'compile', sb_path, '-o', sb_srs_path], check=True)
            print(f"Successfully compiled Singbox SRS: {g_name}.srs")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error: Failed to compile {g_name}.json to SRS: {e}")

# ==========================================
# 6. 主控业务流程入口
# ==========================================
def main():
    router_cleaned = {}
    allocated_names = set()
    
    # 1. 路由表清洗与本地源发现
    for policy_card in FILE_POLICY_ROUTER:
        raw_name = policy_card.get('name', '')
        real_name = get_smart_base_name(raw_name, policy_card, allocated_names)
        allocated_names.add(real_name)
        router_cleaned[real_name] = policy_card

    normalize_and_discover_local_sources(router_cleaned)

    # 动态初始化平台数据收集容器
    global_matrix = {plat: {} for plat in GLOBAL_PLATFORM_MATRIX.keys()}

    # 2. 多线程拉取、合并加工与 Mihomo MRS 二进制转换
    for target_base_name, policy_card in router_cleaned.items():
        rules_in_memory = fetch_and_merge_rules(target_base_name, policy_card)       
        dispatch_rules_to_targets(target_base_name, policy_card, rules_in_memory, global_matrix)
        compile_mihomo_mrs(target_base_name, policy_card, rules_in_memory)
  
    # 提取输出目录映射（为后半段的落盘做准备）
    output_directories = {plat: cfg['dir'] for plat, cfg in GLOBAL_PLATFORM_MATRIX.items()}


    # 3. 终极域名敛并优化（调用外部处理器：rules_processor）
    for plat, targets in global_matrix.items():
        for target_name, rules in targets.items():
            if isinstance(rules, dict):
                rules_processor.optimize_domains(rules)

    # 4. 动态导出并调用格式化模块（调用外部格式化器：rules_formatter）
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )

    # 5. Singbox SRS 后置二进制打包编译
    compile_singbox_srs(global_matrix, output_directories['singbox'])


if __name__ == '__main__':
    main()
