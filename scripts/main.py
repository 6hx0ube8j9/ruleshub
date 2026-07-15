# -*- coding: utf-8 -*-
import os
import json
import asyncio
import aiohttp
import subprocess
import sys
import urllib.request
import urllib.error

import rules_loader
import rules_formatter
import rules_processor

# =========================================================================
# 1. 基础路径与工具链定义
# =========================================================================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__)) 
RULESET_JSON_PATH = os.path.join(SCRIPT_DIR, 'ruleset.json')
MIHOMO_BIN        = os.path.join(SCRIPT_DIR, 'mihomo-bin')
SINGBOX_BIN       = os.path.join(SCRIPT_DIR, 'sing-box')

# =========================================================================
# 2. 📂 阶段 2：数据源同步 (sync_source)
# =========================================================================
async def fetch_single_url_async(session, url):
    """
    网络异步拉取任务，支持 15 秒超时保护。
    网络异常时返回 None，成功但内容为空时返回空列表 []，以此作为精准区分。
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        async with session.get(url, headers=headers, timeout=15) as response:
            if response.status == 200:
                text = await response.text(encoding='utf-8', errors='ignore')
                return url, text.splitlines()
            else:
                print(f"⚠️ Warning: Fetch failed for {url} with status {response.status}")
                return url, None
    except Exception as e:
        print(f"⚠️ Warning: Fetch failed for {url} - {e}")
        return url, None

async def async_fetch_all(urls_list):
    """
    第一步：并发拉取至内存，不在本阶段写入磁盘。
    """
    if not urls_list:
        return {}
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_single_url_async(session, url) for url in urls_list]
        results = await asyncio.gather(*tasks)
        return dict(results)

def sync_to_disk(sync_config, fetched_data):
    """
    第二步：本地串行合并并落盘。
    🎯 修复点：确保合并本地和网络数据时，文件名、后缀等文件系统属性小写归一化。
    🚨 下游克制：不在下游直接调用 .lower() 处理行文本数据，全部交给 rules_processor 进行清洗。
    """
    if not sync_config:
        return

    source_keys = rules_processor.source_keys

    for url, targets in sync_config.items():
        if isinstance(targets, str):
            target_list = [targets]
        elif isinstance(targets, list):
            target_list = targets
        else:
            continue
        
        remote_lines = fetched_data.get(url)
        # 👑 区分：只有当拉取结果物理上为 None 时，才被判定为“网络层拉取失败”以保护本地数据
        if remote_lines is None:
            print(f"⚠️ [下载失败] 网络同步源下载失败，跳过本次覆盖更新: {url}")
            continue
            
        for target in target_list:
            target = target.strip().lower()
            if not target:
                continue
            filename = target if target.endswith('.txt') else f"{target}.txt"
            file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
            pure_name = os.path.splitext(filename)[0]
            
            # 🛡️ 物理大小写自愈防线：
            # 如果磁盘上存在旧的、带有大写字母的文件（如 MyRules.TXT），写入纯小写新文件前将其彻底删除，防止残留
            for raw_f in os.listdir(rules_loader.SOURCE_DIR):
                if raw_f.lower() == filename and raw_f != filename:
                    try:
                        os.remove(os.path.join(rules_loader.SOURCE_DIR, raw_f))
                    except Exception:
                        pass
            
            local_raw = load_local_raw_lines(file_path)
            
            cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, remote_lines)

            save_local_rules(file_path, pure_name, cleaned_rules, source_keys)
            print(f"💾 [合并写入] 网络源 {url} 已合并写入本地: {filename}")

def load_local_raw_lines(source_path):
    """
    安全读取本地规则，进行换行符归一化重构。
    """
    if not os.path.exists(source_path):
        return []
    with open(source_path, 'r', encoding='utf-8') as f:
        return f.read().splitlines()

def save_local_rules(source_path, source_file_name, rules, rule_keys):
    """
    保存清洗后的本地源规则。
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
                
def format_local_sources():
    """
    本地源文件自动格式化
    🎯 修复点：物理文件名强制转换为纯小写，解决 Linux/Docker 下因大小写敏感导致的文件找不到隐患。
    🚨 下游克制：不对读取的行内容进行任何小写转换，数据层清洗全权交给 rules_processor。
    """
    if not os.path.exists(rules_loader.SOURCE_DIR):
        return

    print("🧹 [格式化] 正在整理本地 source/ 目录下的规则源文件...")
    source_keys = rules_processor.source_keys
    formatted_count = 0

    for filename in os.listdir(rules_loader.SOURCE_DIR):
        # 兼容大写后缀 .TXT 或 .Txt
        if not filename.lower().endswith('.txt'):
            continue
            
        old_file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
        
        # 物理文件名强制小写化，规避 Linux 大小写敏感陷阱
        lower_filename = filename.lower()
        new_file_path = os.path.join(rules_loader.SOURCE_DIR, lower_filename)
        pure_name = os.path.splitext(lower_filename)[0]
        
        # 读取本地原文件（保持原汁原味，不作下游小写修改）
        local_raw = load_local_raw_lines(old_file_path)
        if not local_raw:
            continue
            
        # 提交给上游清洗管道
        cleaned_rules = rules_processor.execute_rules_pipeline(local_raw, [])
        
        # 重新写回本地物理文件（确保路径是纯小写）
        save_local_rules(new_file_path, pure_name, cleaned_rules, source_keys)
        
        # 若原文件名存在大写字母，在 Linux 下需要删掉旧的大写文件，防止残留
        if old_file_path != new_file_path:
            try:
                os.remove(old_file_path)
            except Exception:
                pass
                
        formatted_count += 1

    print(f"🧹 [格式化] 本地规则源文件整理完毕，共格式化 {formatted_count} 个文件。")
    
# =========================================================================
# 3. 📦 阶段 3：策略组规则构建与分发 (groups)
# =========================================================================
def build_group_rules(group_config):
    """
    构建策略组的内存规则集。仅对本地物理 source 目录进行只读访问。
    🎯 修复点：确保本地组件引用脱敏，同时坚决不污染网络 URL 和规则内容数据。
    """
    group_name = group_config['name']
    inputs = group_config.get('inputs')
    
    all_local_raw = []
    all_remote_raw = []
    
    # 2.1 inputs 缺省：默认读取本地同名纯小写规则文件
    if inputs is None:
        filename = f"{group_name.lower()}.txt"
        file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
        if not os.path.exists(file_path):
            print(f"⚠️ [WARN] 策略组 '{group_name}' 未指定 inputs 且本地文件 '{filename}' 不存在，跳过该组。")
            return None
        all_local_raw.extend(load_local_raw_lines(file_path))
    
    # 2.2 inputs 显式定义：加载全部输入规则源
    else:
        if not isinstance(inputs, list):
            inputs = [inputs]
            
        for inp in inputs:
            inp_str = str(inp).strip()
            if not inp_str:
                continue
            
            # 🔒 护城河：如果是远程网络源，保持原始 URL 大小写，绝对不可调用 .lower()
            if inp_str.startswith('http://') or inp_str.startswith('https://'):
                print(f"🌐 [网络载入] 正在获取网络规则 (内存暂存): {inp_str}")
                try:
                    req = urllib.request.Request(inp_str, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        lines = response.read().decode('utf-8', errors='ignore').splitlines()
                        all_remote_raw.extend(lines) # 保持原汁原味投递给上游
                except urllib.error.HTTPError as e:
                    print(f"⚠️ [WARN] 网络源拉取失败，HTTP状态码: {e.code} ({inp_str})")
                except urllib.error.URLError as e:
                    print(f"⚠️ [WARN] 网络连接失败，原因: {e.reason} ({inp_str})")
                except Exception as e:
                    print(f"⚠️ [WARN] 网络拉取异常: {e} ({inp_str})")
            
            # 📁 本地文件引用：将引用名进行小写归一化，精准定位物理磁盘文件
            else:
                clean_name = inp_str.lower()
                filename = clean_name if clean_name.endswith('.txt') else f"{clean_name}.txt"
                file_path = os.path.join(rules_loader.SOURCE_DIR, filename)
                if os.path.exists(file_path):
                    all_local_raw.extend(load_local_raw_lines(file_path))
                else:
                    print(f"⚠️ [WARN] 引用的本地源文件 '{filename}' 不存在，跳过此源。")
                    
    # 🚚 统一交付：下游全过程未对行数据进行任何 .lower()，在此处一次性提交给上游管道清洗去重
    final_rules = rules_processor.execute_rules_pipeline(all_local_raw, all_remote_raw)
    return final_rules

def dispatch_to_matrix(group_name, group_config, rules, global_matrix):
    """
    根据配置的路由决策，将已合并的策略组规则分发注入到全局矩阵中。
    """
    routing_map = rules_loader.resolve_routing(group_config, group_name)
    outputs = group_config.get('outputs', {})
    
    for plat in rules_loader.ROUTING_MATRIX.keys():
        if plat not in routing_map:
            continue
            
        target_name = routing_map[plat]
        
        if not isinstance(target_name, str) or not target_name:
            continue
                
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
        else:
            if target_name not in global_matrix[plat]:
                global_matrix[plat][target_name] = {k: set() for k in rules.keys()}
            for k, v in rules.items():
                global_matrix[plat][target_name][k].update(v)


def compile_mihomo_mrs(base_name, group_config, rules):
    """
    调用 rules_loader 处理 Mihomo 隧道的分流路由，并使用工具链执行编译。
    """
    if not os.path.exists(MIHOMO_BIN):
        return
    
    routing_map = rules_loader.resolve_routing(group_config, base_name)
    mrs_tunnels = ['mihomo_ipcidr', 'mihomo_domain']
    
    for tunnel_type in mrs_tunnels:
        if tunnel_type not in routing_map: 
            continue

        target_name = routing_map[tunnel_type]
        if not isinstance(target_name, str) or not target_name:
            continue
            
        sub_dir = 'ipcidr' if tunnel_type == 'mihomo_ipcidr' else 'domain'
        
        formatter = getattr(rules_formatter, f"generate_{tunnel_type}", None)
        content = formatter(rules) if formatter else ""
        if not content: 
            continue

        yaml_path = os.path.join(rules_loader.MIHOMO_DIR, sub_dir, f"{target_name}.yaml")
        mrs_out_path = os.path.join(rules_loader.MIHOMO_DIR, sub_dir, f"{target_name}.mrs")
        
        try:
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(content)
            subprocess.run([MIHOMO_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], check=True, capture_output=True)
            print(f"✅ Compiled MRS: {target_name}.mrs ({sub_dir})")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to compile {target_name} ({sub_dir})")

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
        except subprocess.CalledProcessError:
            print(f"❌ Failed to compile SRS: {g_name}.json")

# =========================================================================
# 5. 主程序生命周期控制中心 (Main Execution Loop)
# =========================================================================
def main():
    # ---------------------------------------------------------------------
    # 【 阶段 1：载入与配置文件预清洗 】
    # ---------------------------------------------------------------------
    print("【 阶段 1：载入规则配置 】运行中...")
    try:
        config_data = rules_loader.load_and_prepare_config(RULESET_JSON_PATH)
    except (FileNotFoundError, ValueError) as e:
        print(f"❌ {e}")
        sys.exit(1)

    sync_source = config_data.get('sync_source', {})
    groups = config_data.get('groups', [])
    
    # 🛡️ 核心前置防御：在干任何事之前，先重命名并洗平本地 source/ 目录下的所有大小写文件名隐患
    format_local_sources()

    # ---------------------------------------------------------------------
    # 【 阶段 2：数据源同步 】
    # ---------------------------------------------------------------------
    print("\n【 阶段 2：同步本地规则库 】运行中...")
    urls_to_fetch = list(sync_source.keys())
    if urls_to_fetch:
        print(f"🌐 正在启动异步并发请求（总计 {len(urls_to_fetch)} 个网络规则源）...")
        fetched_data = asyncio.run(async_fetch_all(urls_to_fetch))
        print("💾 正在将同步的数据合并写入本地存储...")
        # sync_to_disk 内部已对 target 执行小写化，会精准覆写或创建纯小写本地文件
        sync_to_disk(sync_source, fetched_data)
    else:
        print("ℹ️ 无定义的网络同步源，跳过同步步骤。")

    # ---------------------------------------------------------------------
    # 【 阶段 3：策略组规则构建与分发 】
    # ---------------------------------------------------------------------
    print("\n【 阶段 3：策略组规则分发 】运行中...")
    global_matrix = {plat: {} for plat in rules_loader.ROUTING_MATRIX.keys()}
    group_rules_cache = {}  
    
    for group_config in groups:
        group_name = group_config.get('name')
        if not group_name:
            continue
            
        print(f"📦 正在构建与分发策略组规则: {group_name}")
        rules_in_memory = build_group_rules(group_config)
        if rules_in_memory is None:
            continue
            
        group_rules_cache[group_name] = (group_config, rules_in_memory)
        dispatch_to_matrix(group_name, group_config, rules_in_memory, global_matrix)

    # ---------------------------------------------------------------------
    # 【 阶段 4：导出与二进制编译 】
    # ---------------------------------------------------------------------
    print("\n【 阶段 4：平台文件导出与编译 】运行中...")
    
    output_directories = {
        plat: cfg['dir'] 
        for plat, cfg in rules_loader.ROUTING_MATRIX.items() 
        if 'dir' in cfg and plat not in ('mihomo_ipcidr', 'mihomo_domain')
    }
    
    # 4.1. 导出文本文件
    rules_formatter.export_all(
        global_matrix = global_matrix,
        dir_map = output_directories
    )
    
    # 4.2. 编译 Mihomo MRS 格式二进制文件
    for group_name, (group_config, rules) in group_rules_cache.items():
        compile_mihomo_mrs(group_name, group_config, rules)
        
    # 4.3. 编译 Sing-box SRS 格式二进制文件
    if 'singbox' in output_directories:
        compile_singbox_srs(global_matrix, output_directories['singbox'])

if __name__ == '__main__':
    main()
