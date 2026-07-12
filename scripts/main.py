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
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                  # /project

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
        'blacklist': ['classic', 'nodomain']
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
REQUIRED_DIRS = {
    RULESET_BASE_DIR, 
    SOURCE_DIR, 
    MIHOMO_DIR,
    os.path.join(MIHOMO_DIR, 'domain'),
    os.path.join(MIHOMO_DIR, 'ipcidr')
}

REQUIRED_DIRS.update(plat_cfg['dir'] for plat_cfg in GLOBAL_PLATFORM_MATRIX.values() if 'dir' in plat_cfg)

for d in sorted(REQUIRED_DIRS):
    os.makedirs(d, exist_ok=True)

if not os.path.exists(RULESET_JSON_PATH):
    with open(RULESET_JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump([], f, indent=2, ensure_ascii=False)

try:
    with open(RULESET_JSON_PATH, 'r', encoding='utf-8') as f:
        FILE_POLICY_ROUTER = json.load(f)
except json.JSONDecodeError as e:
    print(f"\n❌ ruleset.json [{e.lineno}:{e.colno}] -> {e.msg}\n")
    import sys
    sys.exit(1) 

# ==========================================
# 4. 基础工具函数集与决策引擎
# ==========================================
# 重构代码
def normalize_policy_card(policy, base_name):
    """
    数据防腐层 (Anti-Corruption Layer)
    动态提取矩阵配置，将卡片中所有工具字段及 source 字段的 "true"、True、"" 强行重写归一化为最具象化的 base_name
    """
    target_fields = ['source']
    for cfg in GLOBAL_PLATFORM_MATRIX.values():
        if 'field' in cfg: target_fields.append(cfg['field'])
    for cfg in MIHOMO_MRS_TUNNEL_MATRIX.values():
        if 'field' in cfg: target_fields.append(cfg['field'])

    for field in target_fields:
        if field not in policy:
            continue
        
        val = policy[field]
        
        if isinstance(val, list):
            if any(str(x).lower() == 'false' for x in val):
                policy[field] = False
            else:
                cleaned = []
                for x in val:
                    x_str = str(x).strip()
                    if x_str.lower() == 'true' or x_str == '':
                        cleaned.append(base_name)
                    else:
                        cleaned.append(x_str.lower())
                policy[field] = list(dict.fromkeys(cleaned))
        
        elif val is not None:
            val_str = str(val).strip()
            if val_str.lower() == 'false':
                policy[field] = False
            elif val_str.lower() == 'true' or val_str == '':
                policy[field] = base_name
            else:
                policy[field] = val_str

# 重构代码
def evaluate_routing_decision(policy, config, base_name):
    """
    统一路由决策引擎
    职责: 收拢所有平台的黑名单、白名单、显式开关、别名更名、正则保底等过滤逻辑
    返回: (is_enabled: bool, target_name: str or None)
    """
    field_name = config.get('field')
    val = policy.get(field_name)
    name_lower = base_name.lower()

    # 1. 最高优先级：物理黑名单拦截（如 Mihomo MRS 的 classic, nodomain）
    if 'blacklist' in config and any(b in name_lower for b in config['blacklist']):
        return False, None

    # 2. 最高优先级：显式赋值为 False / 'false'，强行拦截跳过
    if val is False or str(val).lower() == 'false':
        return False, None

    # 3. 特殊平台分流分支 A：PAC 白名单机制与独立逻辑
    if field_name == 'pac':
        if val is True or str(val).lower() == 'true' or name_lower in config.get('whitelist', []):
            return True, base_name
        if isinstance(val, str) and val.strip():
            return True, val.strip()
        return False, None

    # 4. 特殊平台分流分支 B：Mihomo MRS 二进制规则集的正则/强开判定
    if 'regex' in config:
        has_explicit_value = (val is not None) and (str(val).strip() != "")
        if has_explicit_value:
            return True, base_name
        # 激活名称正则保底机制
        if re.search(config['regex'], name_lower):
            return True, base_name
        return False, None

    # 5. 通用流 (Loon, Singbox, QX, Shadowrocket, mhm_classical, source 等)
    if val is None or val == '' or val is True or str(val).lower() == 'true':
        return True, base_name
        
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
    if not os.path.exists(source_path):
        return []
    with open(source_path, 'r', encoding='utf-8') as f_local:
        return f_local.readlines() 


# 重构代码
def load_remote_raw_lines_mapped(url_list):

    if not url_list:
        return {}
    result_map = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(fetch_single_url, url): url for url in url_list}
        for future in as_completed(future_to_url):
            url, lines = future.result()
            result_map[url] = lines
    return result_map


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

# 重构代码        
def parse_source_config(base_name, policy):

    source_cfg = policy.get('source', None)
    
    if source_cfg is False:
        return False, []
        
    if source_cfg is None or (isinstance(source_cfg, list) and len(source_cfg) == 0):
        return True, [base_name.lower()]

    if isinstance(source_cfg, list):
        return True, [str(x) for x in source_cfg]

    if isinstance(source_cfg, str):
        return True, [source_cfg]
        
    return True, []
    
# 重构代码    
def fetch_and_merge_rules(base_name, policy):
    source_enable, source_list = parse_source_config(base_name, policy)
    
    urls_config = policy.get('url', [])
    if not isinstance(urls_config, list):
        urls_config = [urls_config] if urls_config else []
        
    all_remote_urls = []
    url_to_sync_target = {}
    
    for item in urls_config:
        url_str = item.get('url', '') if isinstance(item, dict) else (item if isinstance(item, str) else '')
        sync_target = item.get('sync_source', False) if isinstance(item, dict) else False
        
        if url_str:
            all_remote_urls.append(url_str)
            if isinstance(sync_target, str):
                sf_name = base_name.lower() if sync_target == "" else sync_target.lower()
                if not sf_name.endswith('.txt'): sf_name += '.txt'
                url_to_sync_target[url_str] = sf_name

    remote_data_map = load_remote_raw_lines_mapped(all_remote_urls)

    if source_enable and url_to_sync_target:
        sync_tasks = {}
        for url_str, sf_name in url_to_sync_target.items():
            t_path = os.path.join(SOURCE_DIR, sf_name)
            p_name = os.path.splitext(sf_name)[0]
            if t_path not in sync_tasks:
                sync_tasks[t_path] = {"pure_name": p_name, "remote_lines": []}
            sync_tasks[t_path]["remote_lines"].extend(remote_data_map.get(url_str, []))
            
        for target_path, task in sync_tasks.items():
            sub_local_raw = load_local_raw_lines(target_path)
            sub_rules = rules_processor.execute_rules_pipeline(sub_local_raw, task["remote_lines"])
            save_local_rules(target_path, task["pure_name"], sub_rules, rules_processor.source_keys, source_enable)

    all_local_raw = []
    if source_enable:
        for src_item in source_list:
            if not isinstance(src_item, str): continue
            if not src_item.endswith('.txt'): src_item += '.txt'
            src_path = os.path.join(SOURCE_DIR, src_item.lower())
            if not os.path.exists(src_path): continue
            all_local_raw.extend(load_local_raw_lines(src_path))

    all_remote_raw = []
    for lines in remote_data_map.values():
        all_remote_raw.extend(lines)

    final_rules = rules_processor.execute_rules_pipeline(all_local_raw, all_remote_raw)
    
    rules_processor.optimize_domains(final_rules)
    
    return final_rules

def save_local_rules(source_path, source_file_name, rules, rule_keys, source_enable):
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

# 重构代码
def dispatch_rules_to_targets(base_name, policy, rules, global_matrix):
    """将内存中的规则分流到各平台对应的全局矩阵结构中"""
    for plat, config in GLOBAL_PLATFORM_MATRIX.items():
        # 统一调用决策引擎
        enabled, target_name = evaluate_routing_decision(policy, config, base_name)
        if not enabled:
            continue

        # 针对不同数据结构进行微调落盘（属于平台特性，不属于路由决策）
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
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = set()
            global_matrix[plat][target_name].update(rules.get('suffix', set()))
            global_matrix[plat][target_name].update(rules.get('full', set()))
            
        else:
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = {k: set() for k in rules.keys()}
            for k, v in rules.items():
                global_matrix[plat][target_name][k].update(v)

# 重构代码
def normalize_and_discover_local_sources(router_cleaned):
    if not os.path.exists(SOURCE_DIR): 
        return
        
    explicitly_consumed_sources = set()
    for b_name, policy in router_cleaned.items():
        source_cfg = policy.get('source', None)
        
        if source_cfg is None or source_cfg is True or (isinstance(source_cfg, list) and len(source_cfg) == 0):
            explicitly_consumed_sources.add(b_name.lower())
        elif isinstance(source_cfg, list):
            for item in source_cfg:
                if isinstance(item, str):
                    explicitly_consumed_sources.add(os.path.splitext(item.lower())[0])
        elif isinstance(source_cfg, str):
            explicitly_consumed_sources.add(os.path.splitext(source_cfg.lower())[0])
        
    for f in os.listdir(SOURCE_DIR):
        if f.endswith('.txt'):
            if not f.islower():
                old_path = os.path.join(SOURCE_DIR, f)
                new_f = f.lower()
                new_path = os.path.join(SOURCE_DIR, new_f)
                if os.path.exists(new_path):
                    try:
                        with open(old_path, 'r', encoding='utf-8') as f_old: old_content = f_old.read()
                        with open(new_path, 'a', encoding='utf-8') as f_new: f_new.write("\n" + old_content)
                        os.remove(old_path)
                    except Exception as e: print(f"⚠️ [WARN] Failed to merge local source '{f}': {e}")
                else:
                    try: os.rename(old_path, new_path)
                    except Exception as e: print(f"⚠️ [WARN] Failed to rename local source '{f}': {e}")
                f = new_f

            local_base_name = os.path.splitext(f)[0]
            
            if local_base_name in router_cleaned or local_base_name in explicitly_consumed_sources: 
                continue
            router_cleaned[local_base_name] = {'name': local_base_name, 'url': []}

def compile_mihomo_mrs(base_name, policy, rules):
    """将 YAML 规则集过滤、清洗并编译为 Mihomo 二进制 .mrs 格式"""
    if not os.path.exists(MIHOMO_BIN):
        print(f"❌ Error: '{MIHOMO_BIN}' not found.")
        return

    name_lower = base_name.lower()
    
    for tunnel_type, config in MIHOMO_MRS_TUNNEL_MATRIX.items():
        # 统一调用决策引擎，MRS 是否需要编译一目了然
        enabled, _ = evaluate_routing_decision(policy, config, base_name)
        if not enabled: 
            continue

        # 动态路由派发与编译逻辑
        sub_dir = tunnel_type.split('_')[1]
        formatter = getattr(rules_formatter, f"generate_{tunnel_type}", None)
        content = formatter(rules) if formatter else ""
        if not content: continue

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
    
    # 1. 路由表清洗、入口数据防腐归一化与本地源发现
    for policy_card in FILE_POLICY_ROUTER:
        raw_name = policy_card.get('name', '')
        real_name = get_smart_base_name(raw_name, policy_card, allocated_names)
        allocated_names.add(real_name)
        
        normalize_policy_card(policy_card, real_name)
        
        router_cleaned[real_name] = policy_card

    normalize_and_discover_local_sources(router_cleaned)

    # 动态初始化平台数据收集容器
    global_matrix = {plat: {} for plat in GLOBAL_PLATFORM_MATRIX.keys()}

    # 2. 多线程拉取、合并加工与 Mihomo MRS 二进制转换
    for target_base_name, policy_card in router_cleaned.items():
        rules_in_memory = fetch_and_merge_rules(target_base_name, policy_card)       
        dispatch_rules_to_targets(target_base_name, policy_card, rules_in_memory, global_matrix)
        compile_mihomo_mrs(target_base_name, policy_card, rules_in_memory)
  
    # 提取输出目录映射
    output_directories = {plat: cfg['dir'] for plat, cfg in GLOBAL_PLATFORM_MATRIX.items()}

    # 3. 终极域名敛并优化
    for plat, targets in global_matrix.items():
        for target_name, rules in targets.items():
            if isinstance(rules, dict):
                rules_processor.optimize_domains(rules)

    # 4. 动态导出并调用格式化模块
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )

    # 5. Singbox SRS 后置二进制打包编译
    compile_singbox_srs(global_matrix, output_directories['singbox'])


if __name__ == '__main__':
    main()
