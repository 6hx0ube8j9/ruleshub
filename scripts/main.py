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
SOURCE_DIR       = os.path.join(SCRIPT_DIR, 'source')
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
    【防腐层终极觉醒：支持双向改写与防呆容错】
    """
    target_fields = ['source']
    for cfg in GLOBAL_PLATFORM_MATRIX.values():
        if 'field' in cfg: target_fields.append(cfg['field'])
    for cfg in MIHOMO_MRS_TUNNEL_MATRIX.values():
        if 'field' in cfg: target_fields.append(cfg['field'])

    base_name_lower = base_name.lower()

    # --- 新增逻辑：精准清洗并改写新版 url 字典矩阵 ---
    if 'url' in policy and isinstance(policy['url'], dict):
        for u, act in list(policy['url'].items()):
            # 如果发现值是空字符串，在内存中等价改写为布尔值 False (回写 JSON 后即为 false)
            if act == '' or (isinstance(act, str) and act.strip() == ''):
                policy['url'][u] = False

    # --- 原有矩阵字段清洗（融入拼写手误防呆） ---
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
                    # 容错防呆：同时识别 'true' 和拼错的 'ture'
                    if x_str.lower() in ['true', 'ture'] or x_str == '':
                        cleaned.append(base_name_lower)
                    else:
                        cleaned.append(x_str)
                policy[field] = list(dict.fromkeys(cleaned))
        
        elif val is not None:
            val_str = str(val).strip()
            if val_str.lower() == 'false':
                policy[field] = False
            # 容错防呆：同时识别 'true' 和拼错的 'ture'
            elif val_str.lower() in ['true', 'ture'] or val_str == '':
                policy[field] = base_name_lower
            else:
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
	
def _extract_and_normalize_routes(base_name, urls_config):
    """
    【重构：网络矩阵解析官】
    适配新版扁平化单大括号字典模型。
    1. 100% 提取所有 URL 键名，建立无门控全量通航的物理基础。
    2. 精准提炼 "sync:" 动作，构建纯净的物理落盘映射表。
    """
    all_remote_urls = []
    sync_map = {}
    
    if not isinstance(urls_config, dict):
        return all_remote_urls, sync_map

    for url_str, action in urls_config.items():
        url_str = url_str.strip()
        if not url_str: 
            continue

        # 1. 无门控全量收集所有远程 URL（只要存在，就必须参与并发下载）
        if url_str not in all_remote_urls:
            all_remote_urls.append(url_str)
        
        # 2. 解析落盘意图：仅拦截以 "sync:" 开头的合法动作值
        if isinstance(action, str) and action.strip().lower().startswith('sync:'):
            target_name = action.strip()[5:].strip().lower() 
            if target_name:
                if not target_name.endswith('.txt'): 
                    target_name += '.txt'
                sync_map[url_str] = target_name
                
    return all_remote_urls, sync_map


def _process_local_storage_and_sync(source_enable, source_list, sync_map, remote_data_map):
    """
    【物理存储安全调度中心】
    """
    all_local_raw = []
    processed_filenames = set() 
    
    # --- 第一步：旁路热更新落盘 (带远程规则的复合清洗) ---
    if sync_map:
        for url_str, filename in sync_map.items():
            remote_lines = remote_data_map.get(url_str, [])
            
            if not remote_lines:
                print(f"⚠️ [防空保护] URL 下载失败，已跳过网络覆盖更新: {filename}")
                continue
                
            file_path = os.path.join(SOURCE_DIR, filename)
            pure_name = os.path.splitext(filename)[0]

            local_raw = load_local_raw_lines(file_path)
            cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, remote_lines)
            
            save_local_rules(file_path, pure_name, cleaned_rules, rules_processor.source_keys, True)
            processed_filenames.add(filename)
            print(f"💾 [热更新落盘] 网络与本地成功融合并格式化: {filename}")

    # --- 第二步：本地底稿加载与“纯本地文件”自清洗 (Read & Backup Write) ---
    if source_enable and source_list:
        for src_item in source_list:
            if not isinstance(src_item, str): 
                continue
            filename = src_item.strip().lower()
            if not filename.endswith('.txt'): 
                filename += '.txt'
                
            file_path = os.path.join(SOURCE_DIR, filename)
            
            if os.path.exists(file_path):
                if filename not in processed_filenames:
                    pure_name = os.path.splitext(filename)[0]
                    local_raw = load_local_raw_lines(file_path)
                    
                    cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, [])
                    save_local_rules(file_path, pure_name, cleaned_rules, rules_processor.source_keys, True)
                    
                    processed_filenames.add(filename)
                    print(f"✨ [本地自清洗] 已自动排序、去重并格式化本地物理文件: {filename}")
                
                # 最终，把磁盘上已经绝对干净的规则行加载到大融合内存中
                all_local_raw.extend(load_local_raw_lines(file_path))
            else:
                print(f"⚠️ [提示] 声明的本地底稿文件不存在，已跳过读取: {filename}")
                
    return all_local_raw

def fetch_and_merge_rules(base_name, policy):
    """
    【重构：核心大脑编排官】
    全面贯彻“数据无门控全量通航”理念。
    网络数据流直接在内存中汇合，彻底根除“因设置落盘导致不参与全局合并”的底层 Bug。
    """
    # 1. 导入并解析本地底稿配置
    source_enable, source_list = parse_source_config(base_name, policy)
    
    # 2. 规整新版 URL 字典矩阵配置
    urls_config = policy.get('url', {})
    if not isinstance(urls_config, dict):
        urls_config = {}
        
    # 3. 清洗并提取路由意图（全量 URL 列表 与 精准落盘映射）
    all_remote_urls, sync_map = _extract_and_normalize_routes(base_name, urls_config)

    # 4. 统一发起无门控高并发网络拉取
    remote_data_map = load_remote_raw_lines_mapped(all_remote_urls)

    # 5. 执行解耦调度：旁路安全更新落盘，并要回最新、最干净的本地底稿流
    all_local_raw = _process_local_storage_and_sync(source_enable, source_list, sync_map, remote_data_map)

    # 6. 【核心巨变：无门控通航机制】
    all_remote_raw = []
    for url_str, lines in remote_data_map.items():
        if lines:
            all_remote_raw.extend(lines)

    # 7. 终局纯内存大融合（最新的本地物理底稿 + 100%全量网络流）
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

def dispatch_rules_to_targets(base_name, policy, rules, global_matrix):
    for plat, config in GLOBAL_PLATFORM_MATRIX.items():
        enabled, target_name = evaluate_routing_decision(policy, config, base_name)
        if not enabled:
            continue

        if plat == 'quantumultx':
            policy_cfg_field = config.get('policy_cfg', 'qx_policy')
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
    【架构修复四：稳定安全的本地源发现机制】
    提前处理文件系统的重命名逻辑，规避 IO 延迟引起的幽灵路径问题。
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

    # 将内存中经过防腐层规范化（如纠正 ture、改写 "" 为 false）的配置，重新反向覆写回 ruleset.json 文件
    try:
        with open(RULESET_JSON_PATH, 'w', encoding='utf-8') as f_json:
            json.dump(FILE_POLICY_ROUTER, f_json, indent=2, ensure_ascii=False)
        print("📝 [配置自动重写] ruleset.json 已成功纠正拼写并自动格式化为显式直观模型！")
    except Exception as e:
        print(f"⚠️ [WARN] 反向回写 ruleset.json 失败: {e}")

    global_matrix = {plat: {} for plat in GLOBAL_PLATFORM_MATRIX.keys()}

    # 拉取、独立同步落盘、主线合并加工与 MRS 编译
    for target_base_name, policy_card in router_cleaned.items():
        rules_in_memory = fetch_and_merge_rules(target_base_name, policy_card)       
        dispatch_rules_to_targets(target_base_name, policy_card, rules_in_memory, global_matrix)
        compile_mihomo_mrs(target_base_name, policy_card, rules_in_memory)
  
    output_directories = {plat: cfg['dir'] for plat, cfg in GLOBAL_PLATFORM_MATRIX.items()}

    # 调用格式化模块全平台导出
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )

    # Singbox 二进制编译
    compile_singbox_srs(global_matrix, output_directories['singbox'])

if __name__ == '__main__':
    main()
