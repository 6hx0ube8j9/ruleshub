# -*- coding: utf-8 -*-
import os
import json
import re
import asyncio
import aiohttp
import subprocess
import sys
import urllib.request
import urllib.error

import rules_processor
import rules_formatter

# =========================================================================
# 1. 基础物理路径与工具链定义
# =========================================================================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                  

RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR       = os.path.join(SCRIPT_DIR, 'source')
MIHOMO_DIR       = os.path.join(RULESET_BASE_DIR, 'mihomo')

RULESET_JSON_PATH = os.path.join(SCRIPT_DIR, 'ruleset.json')
MIHOMO_BIN        = os.path.join(SCRIPT_DIR, 'mihomo-bin')
SINGBOX_BIN       = os.path.join(SCRIPT_DIR, 'sing-box')

# =========================================================================
# 2. 平台分发与编译矩阵配置
# =========================================================================
GLOBAL_PLATFORM_MATRIX = {
    'loon':             {'field': 'loon',             'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
    'mihomo_classical': {'field': 'mhm_classical',    'dir': os.path.join(MIHOMO_DIR, 'classical')},    
    'quantumultx':      {'field': 'qx',                'dir': os.path.join(RULESET_BASE_DIR, 'quantumultx')},    
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

# 确保所有基础依赖和输出目录自动补全
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

# =========================================================================
# 3. 🟩 绝对保留并继承的资产 (Core Asset Functions)
# =========================================================================
def normalize_policy_card(group_config):
    """
    配置防腐层。
    清洗并规范化不规范的平台及开关配置（如将拼错的 `ture` 纠正为 `true`）。
    """
    outputs = group_config.get('outputs')
    if outputs is None:
        return
    if isinstance(outputs, dict):
        for platform, val in list(outputs.items()):
            if isinstance(val, str):
                val_lower = val.strip().lower()
                if val_lower in ['true', 'ture', '']:
                    outputs[platform] = True
                elif val_lower == 'false':
                    outputs[platform] = False
                else:
                    outputs[platform] = val.strip()
            elif isinstance(val, bool):
                pass

def evaluate_routing_decision(policy, config, base_name):
    """
    决策真相源。
    负责处理 MRS 正则保底、PAC 白名单分流、黑名单拦截等核心判定逻辑。
    """
    field_name = config.get('field')
    val = policy.get(field_name)
    name_lower = base_name.lower()
    if 'blacklist' in config and any(b in name_lower for b in config['blacklist']):
        return False, None

    if val is False or str(val).lower() == 'false':
        return False, None
    if field_name == 'pac':
        if val is True or str(val).lower() == 'true' or name_lower in config.get('whitelist', []):
            return True, name_lower
        if isinstance(val, str) and val.strip():
            return True, val.strip()
        return False, None
    if 'regex' in config:
        if (val is not None) and (str(val).strip() != ""):
            if str(val).lower() in ['true', 'ture', '']:
                return True, name_lower
            return True, str(val).strip()
        if re.search(config['regex'], name_lower):
            return True, name_lower
        return False, None
    if val is None or val == '' or val is True or str(val).lower() == 'true':
        return True, name_lower
    return True, str(val).strip() 

def build_virtual_policy(group_config):
    """
    无缝桥接函数。维持纯净布尔矩阵，专门服务 evaluate_routing_decision 开关判定。
    """
    outputs = group_config.get('outputs')
    policy = {}
    
    if outputs is None:
        all_fields = []
        for cfg in GLOBAL_PLATFORM_MATRIX.values():
            all_fields.append(cfg['field'])
        for cfg in MIHOMO_MRS_TUNNEL_MATRIX.values():
            all_fields.append(cfg['field'])
        for f in all_fields:
            policy[f] = True
    else:
        for cfg in GLOBAL_PLATFORM_MATRIX.values():
            policy[cfg['field']] = False
        for cfg in MIHOMO_MRS_TUNNEL_MATRIX.values():
            policy[cfg['field']] = False
            
        for k, v in outputs.items():
            if v is not False and str(v).lower() != 'false':
                if k in GLOBAL_PLATFORM_MATRIX:
                    policy[GLOBAL_PLATFORM_MATRIX[k]['field']] = True
                elif k in MIHOMO_MRS_TUNNEL_MATRIX:
                    policy[MIHOMO_MRS_TUNNEL_MATRIX[k]['field']] = True
    return policy

# =========================================================================
# 4. 📂 阶段 2：网络同步总线 (sync_source)
# =========================================================================
async def fetch_single_url_async(session, url):
    """
    网络总线异步拉取任务，支持 15 秒超时保护。
    网络数据使用 splitlines()，不含尾部换行符。
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with session.get(url, headers=headers, timeout=15) as response:
            if response.status == 200:
                text = await response.text(encoding='utf-8', errors='ignore')
                return url, text.splitlines()
            else:
                print(f"⚠️ Warning: Fetch failed for {url} with status {response.status}")
                return url, []
    except Exception as e:
        print(f"⚠️ Warning: Fetch failed for {url} - {e}")
        return url, []

async def async_fetch_all(urls_list):
    """
    第一步：网络并发拉取至内存，严禁在此过程中向磁盘执行物理写入
    """
    if not urls_list:
        return {}
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_single_url_async(session, url) for url in urls_list]
        results = await asyncio.gather(*tasks)
        return dict(results)

def sync_to_disk(sync_config, fetched_data):
    """
    第二步：单线程串行循环落盘。自上而下合并。
    """
    for url, targets in sync_config.items():
        if isinstance(targets, str):
            target_list = [targets]
        elif isinstance(targets, list):
            target_list = targets
        else:
            continue
        
        remote_lines = fetched_data.get(url, [])
        if not remote_lines:
            print(f"⚠️ [防空保护] URL 下载失败，已跳过网络覆盖更新: {url}")
            continue
            
        for target in target_list:
            target = target.strip().lower()
            if not target:
                continue
            filename = target if target.endswith('.txt') else f"{target}.txt"
            file_path = os.path.join(SOURCE_DIR, filename)
            pure_name = os.path.splitext(filename)[0]
            
            # 2.1 读取当前最新的本地底稿文件 (时序继承，已整合 splitlines() 消除换行符隐患)
            local_raw = load_local_raw_lines(file_path)
            
            # 2.2 融汇重组，执行合并清洗流
            cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, remote_lines)
            
            # 2.3 物理覆盖写入磁盘 (已移除冗余的 source_enable 参数)
            source_keys = getattr(rules_processor, 'source_keys', ['suffix', 'full', 'keyword', 'regex', 'ipcidr', 'ipcidr6'])
            save_local_rules(file_path, pure_name, cleaned_rules, source_keys)
            print(f"💾 [时序合并落盘] URL: {url} -> {filename}")

def load_local_raw_lines(source_path):
    """
    【🎯 换行符归一化重构】
    放弃 readlines()，采用 read().splitlines()，
    确保本地读取出来的数据与网络 fetch 返回的列表格式完美对齐，没有多余的 '\\n' 或 '\\r\\n'。
    """
    if not os.path.exists(source_path):
        return []
    with open(source_path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()

def save_local_rules(source_path, source_file_name, rules, rule_keys):
    """
    【🧹 参数冗余优化】
    移除了此前恒定为 True 的 `source_enable` 形参。
    如果没有任何有效规则，静默返回防止空文件被误重写。
    """
    if not any(len(rules.get(k, [])) > 0 for k in rule_keys if k in rules):
        return
    with open(source_path, 'w', encoding='utf-8') as f_source:
        f_source.write(f"# === {source_file_name} Combined Base Rules ===\n\n")
        for r_type in rule_keys:
            if rules.get(r_type):
                f_source.write(f"# --- TYPE: {r_type.upper()} ---\n")
                for val in sorted(rules[r_type]):
                    f_source.write(f"{r_type},{val}\n")
                f_source.write("\n")

# =========================================================================
# 5. 🕋 阶段 3：舱室熔炼分发 (groups)
# =========================================================================
def build_group_rules(group_config):
    """
    熔炼纯净内存规则集。此函数对物理 source/ 仅有只读权。
    """
    group_name = group_config['name']
    inputs = group_config.get('inputs')
    
    all_local_raw = []
    all_remote_raw = []
    
    # 5.1 inputs 缺省：静默读取本地对应 group_name.txt
    if inputs is None:
        filename = f"{group_name.lower()}.txt"
        file_path = os.path.join(SOURCE_DIR, filename)
        if not os.path.exists(file_path):
            print(f"⚠️ [WARN] 舱室 '{group_name}' 缺省 inputs，且本地物理底稿 '{filename}' 不存在！跳过此舱室转换。")
            return None
        all_local_raw.extend(load_local_raw_lines(file_path))
    
    # 5.2 inputs 显式定义：加载全部输入数据源
    else:
        if not isinstance(inputs, list):
            inputs = [inputs]
            
        for inp in inputs:
            inp_str = str(inp).strip()
            if not inp_str:
                continue
            
            # 5.2a 阅后即焚：即时拉取网络源，仅作内存消费，绝不写入物理磁盘
            if inp_str.startswith('http://') or inp_str.startswith('https://'):
                print(f"🌐 [阅后即焚] 正在内存中载入网络规则: {inp_str}")
                try:
                    req = urllib.request.Request(inp_str, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        lines = response.read().decode('utf-8', errors='ignore').splitlines()
                        all_remote_raw.extend(lines)
                except urllib.error.HTTPError as e:
                    print(f"⚠️ [WARN] 阅后即焚拉取失败，HTTP状态码: {e.code} ({inp_str})")
                except urllib.error.URLError as e:
                    print(f"⚠️ [WARN] 阅后即焚连接失败，原因: {e.reason} ({inp_str})")
                except Exception as e:
                    print(f"⚠️ [WARN] 阅后即焚拉取异常: {e} ({inp_str})")
            
            # 5.2b 本地引用：精准定位 source 目录下的声明底稿
            else:
                clean_name = inp_str.lower()
                filename = clean_name if clean_name.endswith('.txt') else f"{clean_name}.txt"
                file_path = os.path.join(SOURCE_DIR, filename)
                if os.path.exists(file_path):
                    all_local_raw.extend(load_local_raw_lines(file_path))
                else:
                    print(f"⚠️ [WARN] 引用的本地底稿 '{filename}' 不存在，跳过此源。")
                    
    # 全权交付外部 rules_processor 进行高能熔炼优化
    final_rules = rules_processor.execute_rules_pipeline(all_local_raw, all_remote_raw)
    rules_processor.optimize_domains(final_rules)
    return final_rules

def dispatch_to_matrix(group_name, group_config, rules, global_matrix):
    """
    读取 outputs 决策，将熔炼完成的内存规则安全注入全局分发矩阵
    """
    policy = build_virtual_policy(group_config)
    outputs = group_config.get('outputs', {})
    
    for plat, config in GLOBAL_PLATFORM_MATRIX.items():
        enabled, target_name = evaluate_routing_decision(policy, config, group_name)
        if not enabled:
            continue
            
        if isinstance(outputs, dict) and plat in outputs:
            plat_val = outputs[plat]
            if plat_val is True or str(plat_val).strip().lower() in ['true', '']:
                target_name = group_name.lower()
            elif isinstance(plat_val, str) and plat_val.strip():
                target_name = plat_val.strip().lower()
                
        if plat == 'quantumultx':
            fallback_label = group_name.capitalize() if group_name.lower() not in ['direct', 'reject'] else group_name.lower()
            qx_policy_label = fallback_label
            if isinstance(outputs, dict) and 'qx_policy' in outputs:
                custom_label = outputs['qx_policy']
                if isinstance(custom_label, str) and custom_label.strip() and str(custom_label).lower() not in ['true', 'false']:
                    qx_policy_label = custom_label.strip()
            
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

# =========================================================================
# 6. ⚙️ 阶段 4：导出与编译 (Export and Compile)
# =========================================================================
def compile_mihomo_mrs(base_name, group_config, rules):
    if not os.path.exists(MIHOMO_BIN):
        return
    policy = build_virtual_policy(group_config)
    outputs = group_config.get('outputs', {})
    
    for tunnel_type, config in MIHOMO_MRS_TUNNEL_MATRIX.items():
        enabled, target_name = evaluate_routing_decision(policy, config, base_name)
        if not enabled: 
            continue

        # 同样对 MRS 编译文件名引入极简降级补全机制
        if isinstance(outputs, dict) and tunnel_type in outputs:
            plat_val = outputs[tunnel_type]
            if plat_val is True or str(plat_val).strip().lower() in ['true', '']:
                target_name = base_name.lower()
            elif isinstance(plat_val, str) and plat_val.strip():
                target_name = plat_val.strip().lower()

        sub_dir = tunnel_type.split('_')[1]
        formatter = getattr(rules_formatter, f"generate_{tunnel_type}", None)
        content = formatter(rules) if formatter else ""
        if not content: 
            continue

        yaml_path = os.path.join(MIHOMO_DIR, sub_dir, f"{target_name.lower()}.yaml")
        mrs_out_path = os.path.join(MIHOMO_DIR, sub_dir, f"{target_name.lower()}.mrs")
        
        try:
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(content)
            # 通过工具链编译成 Mihomo 二进制 ruleset
            subprocess.run([MIHOMO_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], check=True, capture_output=True)
            print(f"✅ Compiled MRS: {target_name.lower()}.mrs ({sub_dir})")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to compile {target_name.lower()} ({sub_dir})")

def compile_singbox_srs(global_matrix, singbox_dir):
    if not os.path.exists(SINGBOX_BIN) or not global_matrix.get('singbox'): 
        return

    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path = os.path.join(singbox_dir, f"{g_name}.json")
        sb_srs_path = os.path.join(singbox_dir, f"{g_name}.srs")

        if not os.path.exists(sb_path): 
            continue

        try:
            # 通过工具链编译成 Sing-box 二进制 srs
            subprocess.run([SINGBOX_BIN, 'rule-set', 'compile', sb_path, '-o', sb_srs_path], check=True, capture_output=True)
            print(f"✅ Compiled SRS: {g_name}.srs")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to compile SRS: {g_name}.json")

# =========================================================================
# 7. 主程序生命周期控制中心 (Main Execution Loop)
# =========================================================================
def main():
    # ---------------------------------------------------------------------
    # 【 阶段 1：载入与规范化 】
    # ---------------------------------------------------------------------
    print("【 阶段 1：载入与规范化 】启动中...")
    if not os.path.exists(RULESET_JSON_PATH):
        print(f"❌ 找不到规则配置文件 ruleset.json: {RULESET_JSON_PATH}")
        sys.exit(1)
        
    try:
        with open(RULESET_JSON_PATH, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ ruleset.json 解析语法错误 [{e.lineno}:{e.colno}] -> {e.msg}")
        sys.exit(1)

    sync_source = config_data.get('sync_source', {})
    groups = config_data.get('groups', [])
    
    # 纯内存配置清洗防腐，不回写磁盘以完整保留原生带排版注释的 json 物理图纸
    for group in groups:
        normalize_policy_card(group)

    # ---------------------------------------------------------------------
    # 【 阶段 2：网络同步总线 】
    # ---------------------------------------------------------------------
    print("\n【 阶段 2：网络同步总线 】启动中...")
    urls_to_fetch = list(sync_source.keys())
    if urls_to_fetch:
        print(f"🌐 正在执行异步高并发拉取（共 {len(urls_to_fetch)} 个网络源）...")
        fetched_data = asyncio.run(async_fetch_all(urls_to_fetch))
        print("💾 正在执行时序串行合并落盘...")
        sync_to_disk(sync_source, fetched_data)
    else:
        print("ℹ️ 未声明网络同步源，跳过同步总线。")

    # ---------------------------------------------------------------------
    # 【 阶段 3：舱室熔炼分发 】
    # ---------------------------------------------------------------------
    print("\n【 阶段 3：舱室熔炼分发 】启动中...")
    global_matrix = {plat: {} for plat in GLOBAL_PLATFORM_MATRIX.keys()}
    group_rules_cache = {}  # 缓存内存熔炼完毕的规则，无缝流转下一阶段
    
    for group_config in groups:
        group_name = group_config.get('name')
        if not group_name:
            continue
            
        print(f"🕋 正在熔炼分发舱室: {group_name}")
        rules_in_memory = build_group_rules(group_config)
        if rules_in_memory is None:
            continue
            
        group_rules_cache[group_name] = (group_config, rules_in_memory)
        dispatch_to_matrix(group_name, group_config, rules_in_memory, global_matrix)

    # ---------------------------------------------------------------------
    # 【 阶段 4：导出与编译 】
    # ---------------------------------------------------------------------
    print("\n【 阶段 4：导出与编译 】启动中...")
    output_directories = {plat: cfg['dir'] for plat, cfg in GLOBAL_PLATFORM_MATRIX.items()}
    
    # 4.1. 调用 rules_formatter 批量导出全平台传统文件
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )
    
    # 4.2. 编译 Mihomo MRS
    for group_name, (group_config, rules) in group_rules_cache.items():
        compile_mihomo_mrs(group_name, group_config, rules)
        
    # 4.3. 编译 Sing-box SRS
    compile_singbox_srs(global_matrix, output_directories['singbox'])
    
    print("\n🌟 [重构成功] 规则分发编译系统终构蓝图圆满完成，生命周期完全隔离！")

if __name__ == '__main__':
    main()
