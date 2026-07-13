# -*- coding: utf-8 -*-
import os
import json
import re
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# 外部公共组件绝对解耦导入
import rules_processor
import rules_formatter

# ==========================================
# 1. 基础物理路径与工具链定义
# ==========================================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                  

RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR       = os.path.join(RULESET_BASE_DIR, 'source')
MIHOMO_DIR       = os.path.join(RULESET_BASE_DIR, 'mihomo')

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
# 3. 运行环境自举
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
def normalize_policy_card(policy, base_name):
    """
    【架构修复一：精细化防腐层】
    只对逻辑控制符 (true/false/"") 归一化。
    原样保留用户手写的自定义别名大小写（如 Quantumult X 的 "Apple", "Proxy"）。
    """
    target_fields = ['source']
    for cfg in GLOBAL_PLATFORM_MATRIX.values():
        if 'field' in cfg: target_fields.append(cfg['field'])
    for cfg in MIHOMO_MRS_TUNNEL_MATRIX.values():
        if 'field' in cfg: target_fields.append(cfg['field'])

    # 强制将基础名称设为小写，确保物理路径调用的绝对安全
    base_name_lower = base_name.lower()

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
                    # 仅改写控制符，绝对禁止对普通字符串 lower()
                    if x_str.lower() == 'true' or x_str == '':
                        cleaned.append(base_name_lower)
                    else:
                        cleaned.append(x_str)
                policy[field] = list(dict.fromkeys(cleaned))
        
        elif val is not None:
            val_str = str(val).strip()
            if val_str.lower() == 'false':
                policy[field] = False
            elif val_str.lower() == 'true' or val_str == '':
                policy[field] = base_name_lower
            else:
                # 原样保留手写别名大小写
                policy[field] = val_str

def evaluate_routing_decision(policy, config, base_name):
    """
    【架构修复二：统一路由决策真相源】
    所有判断逻辑收口于此。对外统一输出明确的 (is_enabled, target_name)。
    """
    field_name = config.get('field')
    val = policy.get(field_name)
    name_lower = base_name.lower()

    # 1. 物理黑名单拦截
    if 'blacklist' in config and any(b in name_lower for b in config['blacklist']):
        return False, None

    # 2. 显式 False 拦截
    if val is False or str(val).lower() == 'false':
        return False, None

    # 3. PAC 白名单分流
    if field_name == 'pac':
        if val is True or str(val).lower() == 'true' or name_lower in config.get('whitelist', []):
            return True, name_lower
        if isinstance(val, str) and val.strip():
            return True, val.strip()
        return False, None

    # 4. MRS 正则保底机制
    if 'regex' in config:
        if (val is not None) and (str(val).strip() != ""):
            return True, str(val).strip()
        if re.search(config['regex'], name_lower):
            return True, name_lower
        return False, None

    # 5. 通用流处理
    if val is None or val == '' or val is True or str(val).lower() == 'true':
        return True, name_lower
        
    # 直接返回包含正确大小写的 val
    return True, str(val).strip() 
    
def get_smart_base_name(name, policy, existing_names):
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
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(remote_url, headers=headers, timeout=15)
        if response.status_code == 200:
            return remote_url, response.content.decode('utf-8', errors='ignore').splitlines()
        return remote_url, []
    except Exception as e:
        print(f"⚠️ Warning: Fetch failed for {remote_url} - {e}")
        return remote_url, []

def parse_source_config(base_name, policy):
    """
    【严密防守：本地源配置解析】
    彻底过滤各种异常类型，确保返回准确的开关状态和文件列表。
    """
    source_cfg = policy.get('source', None)
    
    # 明确拦截 False 或字符串 'false'
    if source_cfg is False or str(source_cfg).strip().lower() == 'false':
        return False, []
    
    # 归一化处理：空、True、空列表皆视为默认映射 base_name.txt
    if source_cfg is None or source_cfg is True or str(source_cfg).strip().lower() == 'true' or (isinstance(source_cfg, list) and len(source_cfg) == 0):
        return True, [base_name.lower()]
        
    if isinstance(source_cfg, list):
        return True, [str(x) for x in source_cfg if str(x).strip().lower() != 'false']
        
    if isinstance(source_cfg, str):
        return True, [source_cfg]
        
    return True, []


def fetch_and_merge_rules(base_name, policy):
    """
    【配置迁移版】严格保持精简版物理管道，仅迁移多源配置解析
    """
    source_file_name = base_name.lower()
    source_path = os.path.join(SOURCE_DIR, f"{source_file_name}.txt")
    
    # ==========================================
    # 1. 迁移完整版的配置解析（仅用于决定拉取哪些数据）
    # ==========================================
    source_enable, source_list = parse_source_config(base_name, policy)
    
    urls_config = policy.get('url', [])
    if not isinstance(urls_config, list):
        urls_config = [urls_config] if urls_config else []
        
    all_remote_urls = []
    for item in urls_config:
        url_str = item.get('url', '') if isinstance(item, dict) else (item if isinstance(item, str) else '')
        if url_str: 
            all_remote_urls.append(url_str)

    # ==========================================
    # 2. 纯物理读取原材料（严格对齐精简版）
    # ==========================================
    # 2.1 收集本地流：如果开启了多源配置则合并读取，否则读取默认同名文件
    all_local_raw = []
    if source_enable and source_list:
        for src_item in source_list:
            if not isinstance(src_item, str): continue
            if not src_item.endswith('.txt'): src_item += '.txt'
            src_path = os.path.join(SOURCE_DIR, src_item.lower())
            all_local_raw.extend(load_local_raw_lines(src_path))
    else:
        all_local_raw = load_local_raw_lines(source_path)
        
    # 2.2 收集网络流：一次性映射拉取全量网络行
    remote_data_map = load_remote_raw_lines_mapped(all_remote_urls)
    all_remote_raw = []
    for lines in remote_data_map.values():
        all_remote_raw.extend(lines)

    # 🎯 节点日志一：检查物理 IO 读到的原始行数
    print(f"\n🔍 [测试断点 1 - 物理读取] 卡片: {base_name}")
    print(f"   ↳ 📝 本地全量原始文本行数: {len(all_local_raw)}")
    print(f"   ↳ 🌐 网络流下载原始文本行数: {len(all_remote_raw)}")

    # ==========================================
    # 3. 衔接大管道（把全量原材料直接喂给底层清洗解耦文件）
    # ==========================================
    final_rules = rules_processor.execute_rules_pipeline(all_local_raw, all_remote_raw)
    
    # 🎯 节点日志二：检查大管道吐出来的数据结构和长度
    print(f"🔍 [测试断点 2 - 管道输出] 经过 execute_rules_pipeline 后:")
    if isinstance(final_rules, dict):
        for k, v in final_rules.items():
            print(f"   ↳ 🔑 Key: [{k}] 里面包含 {len(v)} 条规则 (数据类型: {type(v)})")
    else:
        print(f"   ❌ 警告: 大管道返回的竟然不是字典(dict)类型，而是: {type(final_rules)}")

    # 4. 敛并优化
    rules_processor.optimize_domains(final_rules)
    
    # ==========================================
    # 5. 强制物理落盘（严格对齐精简版无判定拦截写入）
    # ==========================================
    print(f"🔍 [测试断点 3 - 强行落盘] 正在无条件重写: {source_path}")
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {source_file_name} Test Combined Rules ===\n\n")
        
        keys_to_write = getattr(rules_processor, 'source_keys', ['suffix', 'full', 'ip', 'ip6', 'keyword'])
        for r_type in keys_to_write:
            current_data = final_rules.get(r_type, []) if isinstance(final_rules, dict) else []
            if current_data:
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(list(current_data)):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")
                
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

def dispatch_rules_to_targets(base_name, policy, rules, global_matrix):
    for plat, config in GLOBAL_PLATFORM_MATRIX.items():
        enabled, target_name = evaluate_routing_decision(policy, config, base_name)
        if not enabled:
            continue

        if plat == 'quantumultx':
            policy_cfg_field = config.get('policy_cfg', 'qx_policy')
            # 兼容大小写特性的默认策略
            fallback_label = base_name.capitalize() if base_name.lower() not in ['direct', 'reject'] else base_name.lower()
            qx_policy_label = policy.get(policy_cfg_field, fallback_label)
            
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

def normalize_and_discover_local_sources(router_cleaned):
    """
    【架构级联动补丁：稳定安全的本地源发现机制】
    提前处理文件系统的重命名逻辑，规避 IO 延迟引起的幽灵路径问题。
    严格排除机器生成的 .sync.txt 网络缓存，只对纯粹的人类野生底稿进行虚拟卡片映射。
    """
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
        if f.endswith('.txt') and not f.endswith('.sync.txt'):
            if not f.islower():
                old_path = os.path.join(SOURCE_DIR, f)
                new_f = f.lower()
                new_path = os.path.join(SOURCE_DIR, new_f)
                
                if os.path.exists(new_path):
                    try:
                        with open(old_path, 'r', encoding='utf-8') as f_old: old_content = f_old.read()
                        with open(new_path, 'a', encoding='utf-8') as f_new: f_new.write("\n" + old_content)
                        os.remove(old_path)
                    except Exception as e: print(f"⚠️ [WARN] Merge failed for '{f}': {e}")
                else:
                    try: os.rename(old_path, new_path)
                    except Exception as e: print(f"⚠️ [WARN] Rename failed for '{f}': {e}")
                f = new_f

            local_base_name = os.path.splitext(f)[0]
            if local_base_name in router_cleaned or local_base_name in explicitly_consumed_sources: 
                continue

            router_cleaned[local_base_name] = {'name': local_base_name, 'url': []}

def compile_mihomo_mrs(base_name, policy, rules):
    if not os.path.exists(MIHOMO_BIN):
        return

    for tunnel_type, config in MIHOMO_MRS_TUNNEL_MATRIX.items():
        enabled, _ = evaluate_routing_decision(policy, config, base_name)
        if not enabled: 
            continue

        sub_dir = tunnel_type.split('_')[1]
        formatter = getattr(rules_formatter, f"generate_{tunnel_type}", None)
        content = formatter(rules) if formatter else ""
        if not content: continue

        yaml_path = os.path.join(MIHOMO_DIR, sub_dir, f"{base_name.lower()}.yaml")
        mrs_out_path = os.path.join(MIHOMO_DIR, sub_dir, f"{base_name.lower()}.mrs")
        
        try:
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(content)
            subprocess.run([MIHOMO_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], check=True, capture_output=True)
            print(f"✅ Compiled MRS: {base_name.lower()}.mrs ({sub_dir})")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to compile {base_name.lower()} ({sub_dir})")

def compile_singbox_srs(global_matrix, singbox_dir):
    if not os.path.exists(SINGBOX_BIN) or not global_matrix.get('singbox'): 
        return

    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path = os.path.join(singbox_dir, f"{g_name}.json")
        sb_srs_path = os.path.join(singbox_dir, f"{g_name}.srs")

        if not os.path.exists(sb_path) or not any(raw_rules.values()): 
            continue

        try:
            subprocess.run([SINGBOX_BIN, 'rule-set', 'compile', sb_path, '-o', sb_srs_path], check=True, capture_output=True)
            print(f"✅ Compiled SRS: {g_name}.srs")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to compile SRS: {g_name}.json")

# ==========================================
# 6. 主控业务流程入口
# ==========================================
def main():
    router_cleaned = {}
    allocated_names = set()
    
    # 1. 路由表清洗与入口数据防腐
    for policy_card in FILE_POLICY_ROUTER:
        raw_name = policy_card.get('name', '')
        real_name = get_smart_base_name(raw_name, policy_card, allocated_names)
        allocated_names.add(real_name)
        normalize_policy_card(policy_card, real_name)
        router_cleaned[real_name] = policy_card

    # 优先执行本地源发现机制，稳定文件系统状态
    normalize_and_discover_local_sources(router_cleaned)

    global_matrix = {plat: {} for plat in GLOBAL_PLATFORM_MATRIX.keys()}

    # 2. 拉取、独立同步落盘、主线合并加工与 MRS 编译
    for target_base_name, policy_card in router_cleaned.items():
        rules_in_memory = fetch_and_merge_rules(target_base_name, policy_card)       
        dispatch_rules_to_targets(target_base_name, policy_card, rules_in_memory, global_matrix)
        compile_mihomo_mrs(target_base_name, policy_card, rules_in_memory)
  
    output_directories = {plat: cfg['dir'] for plat, cfg in GLOBAL_PLATFORM_MATRIX.items()}

    # 3. 终极域名敛并优化
    for plat, targets in global_matrix.items():
        for target_name, rules in targets.items():
            if isinstance(rules, dict):
                rules_processor.optimize_domains(rules)

    # 4. 调用格式化模块全平台导出
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )

    # 5. Singbox 二进制编译
    compile_singbox_srs(global_matrix, output_directories['singbox'])

if __name__ == '__main__':
    main()
