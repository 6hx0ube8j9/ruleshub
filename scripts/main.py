# -*- coding: utf-8 -*-
import os
import json
import asyncio
import aiohttp
import subprocess
import sys

import rules_loader
import rules_formatter
import rules_processor

# 阶段 0: 外部调用参数、组件方法与环境常量统一配置区

# 基础网络请求配置
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
FETCH_TIMEOUT   = 15

# 外部物理路径与核心控制矩阵映射
RULESET_CONFIG_PATH     = rules_loader.RULESET_JSON_PATH        # 统一读取 loader 定义的 ruleset.json 路径
MIHOMO_COMPILER_BIN     = rules_loader.MIHOMO_BIN              # 统一读取 loader 校验的 Mihomo 二进制路径
SINGBOX_COMPILER_BIN    = rules_loader.SINGBOX_BIN             # 统一读取 loader 校验的 Sing-box 二进制路径

SOURCE_DIRECTORY        = rules_loader.SOURCE_DIR              # 规则文本落盘/冷备源目录
MIHOMO_OUTPUT_DIR       = rules_loader.MIHOMO_DIR              # Mihomo 专用编译输出父目录
PLATFORM_ROUTING_MATRIX = rules_loader.ROUTING_MATRIX           # 平台路由矩阵控制轴

# 跨模块继承的核心元数据与清洗红线
CONFIG_KEYS             = rules_loader.CONFIG_KEYS             # 动态继承自 loader 的 JSON 配置键名全集
RULE_SOURCE_KEYS        = rules_processor.source_keys          # 清洗管道生成的核心流类型红线

# 外部业务组件核心方法指针绑定
PROCESSOR_PIPELINE      = rules_processor.execute_rules_pipeline # 规则解包清洗主管道函数
FORMATTER_EXPORT_ALL    = rules_formatter.export_all            # 全局各客户端平台文本导出器
MIHOMO_ROUTING = {
    'mihomo_ipcidr': ('ipcidr', rules_formatter.mihomo_ipcidr_text),
    'mihomo_domain': ('domain', rules_formatter.mihomo_domain_text)
}


# 阶段 2: 异步高并发网络拉取引擎

# 异步单链接拉取核心引擎
async def fetch_single_url_async(session, url):
    try:
        print(f"[INFO] 开始拉取网络源: {url}")
        async with session.get(url, headers=DEFAULT_HEADERS, timeout=FETCH_TIMEOUT) as response:
            if response.status == 200:
                text = await response.text(encoding='utf-8', errors='ignore')
                print(f"[SUCCESS] 网络源拉取成功: {url}")
                return url, text.splitlines()
            else:
                print(f"[WARN] 网络源拉取失败 {url} (状态码: {response.status})")
                return url, None
    except Exception as e:
        print(f"[WARN] 网络源拉取异常 {url} (错误: {e})")
        return url, None

# 高并发批量拉取驱动轴
async def fetch_single_with_sem(sem, session, url):
    async with sem:
        return await fetch_single_url_async(session, url)

# 异步发起全量并行拉取任务
async def async_fetch_all(urls_list, max_concurrent=10):
    
    if not urls_list:
        print("[WARN] 待拉取的网络源列表为空")
        return {}
    
    print(f"[INFO] 开始发起高并发网络拉取，最大并发数: {max_concurrent}，总任务数: {len(urls_list)}")
    sem = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(limit=max_concurrent)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_single_with_sem(sem, session, url) for url in urls_list]
        results = await asyncio.gather(*tasks)
        print("[SUCCESS] 所有高并发网络源拉取任务已完成")
        return dict(results)

# 解析配置中所有的网络同步源及 inputs 直连源并激活高并发异步流
async def fetch_all_remote_sources(config_data):
    urls_to_fetch = []
    
    sync_source = config_data.get(CONFIG_KEYS['SOURCES'], {})
    for url in sync_source.keys():
        if url.startswith(('http://', 'https://')):
            urls_to_fetch.append(url)
            
    # 收集 groups 的 inputs 里的直连链接（纯内存直通，阅后即焚）
    groups = config_data.get(CONFIG_KEYS['GROUPS'], [])
    for group in groups:
        inputs = group.get('inputs', [])
        if isinstance(inputs, str):
            inputs = [inputs]
        for inp in inputs:
            inp_str = str(inp).strip()
            if inp_str.startswith(('http://', 'https://')):
                urls_to_fetch.append(inp_str)
                
    urls_to_fetch = list(set(urls_to_fetch))
    print(f"[INFO] 过滤去重完成，共收集到 {len(urls_to_fetch)} 个有效网络源链接")
    return await async_fetch_all(urls_to_fetch)


# 阶段 2.5: 内存沙盒化融合与清洗缓冲

# 内存沙盒化处理器，支持网络拉取与磁盘冷备在内存中完成无缝对齐清洗
def process_sources_in_memory(config_data, fetched_data):
    write_buffer = {}
    sync_source  = config_data.get(CONFIG_KEYS['SOURCES'], {})
    
    for url, targets in sync_source.items():
        if isinstance(targets, str):
            target_list = [targets]
        elif isinstance(targets, list):
            target_list = targets
        else:
            continue
            
        for target in target_list:
            target = target.strip().lower()
            if not target:
                continue
            filename = target if target.endswith('.txt') else f"{target}.txt"
            
            # 统一由顶层全局配置提供的 SOURCE_DIRECTORY 锚定路径
            file_path = os.path.join(SOURCE_DIRECTORY, filename)
            
            # 物理只读式预加载本地快照（作为冷备降级基准）
            local_raw = []
            if os.path.exists(file_path):
                print(f"[INFO] 正在读取本地冷备快照文件: {filename}")
                with open(file_path, 'r', encoding='utf-8') as f:
                    local_raw = f.read().splitlines()
            
            # 内存清洗沙盒化判定
            remote_lines = fetched_data.get(url)
            if remote_lines is not None:
                print(f"[INFO] 正在合并远程更新数据: {filename}")
                cleaned_rules = PROCESSOR_PIPELINE(local_raw, remote_lines)
            else:
                print(f"[WARN] 远程拉取失败 {url}，正在回滚至本地快照: {filename}")
                cleaned_rules = PROCESSOR_PIPELINE(local_raw, [])
                
            write_buffer[file_path] = cleaned_rules
            
    print(f"[SUCCESS] 内存沙盒化融合与清洗完成，缓冲区构建项数: {len(write_buffer)}")
    return write_buffer


# 阶段 3: 内存路由矩阵构建与分配

# 纯内存策略组合并，利用顶层全局红线 RULE_SOURCE_KEYS 驱动计算
def build_group_rules_pure_memory(group_config: dict, write_buffer: dict, fetched_data: dict = None) -> dict:
    if fetched_data is None:
        fetched_data = {}
        
    final_rules = {k: set() for k in RULE_SOURCE_KEYS}
    group_name  = group_config.get('name', '')
    inputs      = group_config.get('inputs', [])

    # 宽容度补全：若未指定 inputs，默认隐式绑定同名本地规则源
    if not inputs:
        default_key  = f"{group_name.lower()}.txt"
        default_path = os.path.join(SOURCE_DIRECTORY, default_key)
        print(f"[INFO] 策略组 {group_name} 未指定输入，默认绑定本地源: {default_key}")
        if default_path in write_buffer:
            inputs = [default_path]
        else:
            if os.path.exists(default_path):
                print(f"[INFO] 从磁盘加载默认本地规则源: {default_path}")
                with open(default_path, 'r', encoding='utf-8') as f:
                    parsed = rules_processor.process_raw_lines_batch(f.readlines(), RULE_SOURCE_KEYS)
                    for k in RULE_SOURCE_KEYS:
                        final_rules[k].update(parsed.get(k, set()))
            return final_rules

    # 纯内存或磁盘跨域合并 + 即时网络直连
    for inp in inputs:
        inp_str = str(inp).strip()
        if not inp_str:
            continue
            
        # 命中网络直连 URL，执行纯内存直通解析，绝不落盘
        if inp_str.startswith(('http://', 'https://')):
            remote_lines = fetched_data.get(inp_str)
            if remote_lines:
                print(f"[INFO] 正在为策略组注入实时网络规则: {group_name}")
                parsed = rules_processor.process_raw_lines_batch(remote_lines, RULE_SOURCE_KEYS)
                for k in RULE_SOURCE_KEYS:
                    final_rules[k].update(parsed.get(k, set()))
            else:
                print(f"[WARN] 内存网络拉取失败或数据为空: {inp_str}")
            continue
            
        # 处理本地文件依赖（沙盒缓冲池或磁盘冷备）
        if os.path.isabs(inp_str):
            buffer_key = inp_str
        else:
            filename   = inp_str if inp_str.lower().endswith('.txt') else f"{inp_str.lower()}.txt"
            buffer_key = os.path.join(SOURCE_DIRECTORY, filename)
        
        if buffer_key in write_buffer:
            target_dict = write_buffer[buffer_key]
            for k in RULE_SOURCE_KEYS:
                if k in target_dict:
                    final_rules[k].update(target_dict[k])
        else:
            # 内存未击中，下沉磁盘捞冷备文件并利用管道二次解析
            if os.path.exists(buffer_key):
                print(f"[INFO] 内存缓冲区未击中，正在从磁盘捞取冷备文件: {buffer_key}")
                with open(buffer_key, 'r', encoding='utf-8') as f:
                    parsed = rules_processor.process_raw_lines_batch(f.readlines(), RULE_SOURCE_KEYS)
                    for k in RULE_SOURCE_KEYS:
                        final_rules[k].update(parsed.get(k, set()))
            else:
                print(f"[WARN] 缓冲区或磁盘中未找到本地文件: {buffer_key}")

    return final_rules

# 提取 Quantumult X 的自定义策略标签
def _extract_qx_policy_label(group_name, outputs):
    if group_name.lower() in ['direct', 'reject']:
        fallback = group_name.lower()
    else:
        fallback = group_name.capitalize()
    
    if isinstance(outputs, dict) and CONFIG_KEYS['QX_POLICY'] in outputs:
        custom_label = outputs[CONFIG_KEYS['QX_POLICY']]
        if isinstance(custom_label, str) and custom_label.strip():
            if custom_label.lower() not in ['true', 'false']:
                return custom_label.strip()
                
    return fallback

# 将解析后的规则分配到多平台全局路由矩阵中
def dispatch_to_matrix(group_name, group_config, rules, global_matrix):
    routing_map = rules_loader.resolve_routing(group_config, group_name)
    outputs     = group_config.get(CONFIG_KEYS['OUTPUTS'], {})
    
    for plat in PLATFORM_ROUTING_MATRIX.keys():
        if plat not in routing_map:
            continue
            
        target_name = routing_map[plat]
        if not isinstance(target_name, str) or not target_name:
            continue
            
        if target_name not in global_matrix[plat]:
            if plat == 'quantumultx':
                global_matrix[plat][target_name] = {
                    'policy_label': _extract_qx_policy_label(group_name, outputs),
                    **{k: set() for k in rules.keys()}
                }
            else:
                global_matrix[plat][target_name] = {k: set() for k in rules.keys()}
                
        target_bucket = global_matrix[plat][target_name]
        for k, v in rules.items():
            if k in target_bucket:
                target_bucket[k].update(v)

# 基于纯内存写缓冲区全面构建下流全局路由矩阵，支持内存级直连注入
def build_routing_matrix_from_buffer(write_buffer, config_data, group_rules_cache, fetched_data):
    global_matrix = {plat: {} for plat in PLATFORM_ROUTING_MATRIX.keys()}
    groups        = config_data.get(CONFIG_KEYS['GROUPS'], [])
    
    for group_config in groups:
        group_name = group_config.get('name')
        if not group_name:
            continue
            
        print(f"[INFO] 正在为策略组 {group_name} 解析内存规则并构建分流矩阵")
        # 传递 fetched_data 开启纯内存网络直连支持
        rules_in_memory = build_group_rules_pure_memory(group_config, write_buffer, fetched_data)
        if rules_in_memory is None:
            continue
            
        group_rules_cache[group_name] = (group_config, rules_in_memory)
        dispatch_to_matrix(group_name, group_config, rules_in_memory, global_matrix)
        
    print("[SUCCESS] 全局多平台路由矩阵构建及分流装配完成")
    return global_matrix


# 阶段 4: 事务提交（原子落盘）与 二进制工具链编译

# 稳健原子级落盘：直接将写缓冲集合展开回写，自适应 Linux 大小写冲突
def commit_write_buffer(write_buffer: dict):
    print(f"[INFO] 开始执行规则源文件的原子级事务提交，待落盘总数: {len(write_buffer)}")
    if not os.path.exists(SOURCE_DIRECTORY):
        os.makedirs(SOURCE_DIRECTORY, exist_ok=True)

    # 执行 Linux 平台潜在的大小写物理冲突强覆盖扫描
    existing_files = os.listdir(SOURCE_DIRECTORY)
    lower_existing = {f.lower(): f for f in existing_files if os.path.isfile(os.path.join(SOURCE_DIRECTORY, f))}

    for file_path, category_dict in write_buffer.items():
        base_name         = os.path.basename(file_path)
        target_lower_name = base_name.lower()

        # 清除大小写残留，为高鲁棒性原子替换清空盲区
        if target_lower_name in lower_existing:
            actual_name = lower_existing[target_lower_name]
            if actual_name != base_name:
                try:
                    os.remove(os.path.join(SOURCE_DIRECTORY, actual_name))
                    print(f"[INFO] 已成功清除冲突的大小写残留文件: {actual_name}")
                except Exception as e:
                    print(f"[WARN] 删除大小写冲突文件失败 {actual_name}: {e}")

        temp_path = f"{file_path}.tmp"

        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(f"# === {base_name} Combined Base Rules ===\n\n")
                for r_type in RULE_SOURCE_KEYS:
                    category_set = category_dict.get(r_type)                    
                    if category_set:
                        f.write(f"# --- TYPE: {r_type.upper()} ---\n")
                        f.writelines(f"{r_type},{val}\n" for val in sorted(category_set))
                        f.write("\n")
                        
            os.replace(temp_path, file_path)
            print(f"[SUCCESS] 规则源原子落盘成功: {base_name}")
        except Exception as e:
            print(f"[ERROR] 文件原子事务保存失败 {base_name}: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)

# 通用工具：原子级写入文件（先写.tmp再替换），防止写入中断导致文件损坏
def safe_write_text(filepath, content):
    temp_path = f"{filepath}.tmp"
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        os.replace(temp_path, filepath)
        return True
    except Exception as e:
        print(f"[ERROR] 安全写入文件失败 {filepath}: {e}")
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except OSError: pass
        return False
        
# 调用外部置顶的 Mihomo 核心二进制工具链执行规则编译
def compile_mihomo_mrs(base_name, group_config, rules):
    if not os.path.exists(MIHOMO_COMPILER_BIN):
        print(f"[WARN] 未找到 Mihomo 二进制编译工具，跳过编译: {MIHOMO_COMPILER_BIN}")
        return
        
    routing_map = rules_loader.resolve_routing(group_config, base_name)
    
    # 直接遍历顶层配置好的策略矩阵
    for tunnel_type, (sub_dir, formatter) in MIHOMO_ROUTING.items():
        
        target_name = routing_map.get(tunnel_type)
        if not target_name or not isinstance(target_name, str):
            continue
            
        content = formatter(rules)
        if not content:
            continue
            
        yaml_path    = os.path.join(MIHOMO_OUTPUT_DIR, sub_dir, f"{target_name}.yaml")
        mrs_out_path = os.path.join(MIHOMO_OUTPUT_DIR, sub_dir, f"{target_name}.mrs")
        
        if not safe_write_text(yaml_path, content):
            continue
            
        try:
            print(f"[INFO] 正在调用 Mihomo 二进制工具链编译 MRS 规则集: {target_name}")
            subprocess.run(
                [MIHOMO_COMPILER_BIN, 'convert-ruleset', sub_dir, 'yaml', yaml_path, mrs_out_path], 
                check=True, capture_output=True, text=True
            )
            print(f"[SUCCESS] 编译 MRS 完成: {target_name}.mrs ({sub_dir})")
        except subprocess.CalledProcessError as e:
            print(f"[WARN] Mihomo 编译失败 {target_name}，退出码: {e.returncode}，错误信息: {e.stderr.strip()}")

# 调用外部置顶的 Sing-box 核心二进制工具链执行规则二进制固化
def compile_singbox_srs(global_matrix, singbox_dir):
    if not os.path.exists(SINGBOX_COMPILER_BIN) or not global_matrix.get('singbox'): 
        print("[WARN] 未找到 Sing-box 编译工具或目标矩阵为空，跳过 SRS 编译")
        return

    for g_name, raw_rules in global_matrix['singbox'].items():
        sb_path     = os.path.join(singbox_dir, f"{g_name}.json")
        sb_srs_path = os.path.join(singbox_dir, f"{g_name}.srs")

        if not os.path.exists(sb_path): 
            print(f"[WARN] 未找到编译所需的 Sing-box JSON 源文件: {sb_path}")
            continue

        try:
            print(f"[INFO] 正在调用 Sing-box 二进制工具链编译 SRS 规则集: {g_name}")
            subprocess.run([SINGBOX_COMPILER_BIN, 'rule-set', 'compile', sb_path, '-o', sb_srs_path], check=True, capture_output=True, text=True)
            print(f"[SUCCESS] 编译 SRS 完成: {g_name}.srs")
        except subprocess.CalledProcessError as e:
            print(f"[WARN] Sing-box 编译失败 {g_name}.json，退出码: {e.returncode}，错误信息: {e.stderr.strip()}")


# 顶层全局异步调度主轴

async def async_main():
    # 阶段 1: 加载配置与环境初始化（严格依赖置顶变量）
    print("[INFO] 阶段 1: 正在加载规则配置...")
    try:
        config_data = rules_loader.load_and_prepare_config(RULESET_CONFIG_PATH)
        print("[SUCCESS] 规则配置文件加载并初始化完成")
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] 配置加载失败: {e}")
        sys.exit(1)

    # 阶段 2: 内存级并行拉取网络源
    print("\n[INFO] 阶段 2: 正在内存中并行拉取远程网络源...")
    fetched_data = await fetch_all_remote_sources(config_data) 
    
    # 阶段 2.5: 沙盒化合并与清洗（完全隔离构建纯内存缓冲池）
    print("\n[INFO] 阶段 2.5: 正在构建纯内存写缓冲区(沙盒化)...")
    try:
        write_buffer = process_sources_in_memory(config_data, fetched_data)
    except Exception as e:
        print(f"[FATAL ERROR] 阶段 2.5 沙盒内存合并失败: {e}")
        sys.exit(1)
        
    # 阶段 3: 纯内存路由矩阵构建与全向分配
    print("\n[INFO] 阶段 3: 正在解析规则并构建路由矩阵...")
    group_rules_cache = {}
    try:
        global_matrix = build_routing_matrix_from_buffer(write_buffer, config_data, group_rules_cache, fetched_data)
    except Exception as e:
        print(f"[FATAL ERROR] 路由矩阵解析失败: {e}")
        sys.exit(1)
        
    # 阶段 4: 原子事务提交与工具链硬编译阶段
    print("\n[INFO] 阶段 4: 正在执行事务提交与工具链编译...")
    try:
        # 1. 批量原子落盘改写用户的本地 .txt 核心规则源文件
        commit_write_buffer(write_buffer)
        
        # 2. 动态过滤提取各平台真实输出目录参数
        output_directories = {
            plat: cfg['dir'] 
            for plat, cfg in PLATFORM_ROUTING_MATRIX.items() 
            if 'dir' in cfg and plat not in ('mihomo_ipcidr', 'mihomo_domain')
        }
        
        # 3. 驱动上游格式化模块全量导出纯文本规则
        print("[INFO] 开始驱动上游格式化模块全量导出各平台纯文本规则")
        FORMATTER_EXPORT_ALL(global_matrix=global_matrix, dir_map=output_directories)
        print("[SUCCESS] 各平台纯文本规则全量导出完成")
        
        # 4. 驱动外部二进制链条执行最终编译固化
        for group_name, (group_config, rules) in group_rules_cache.items():
            compile_mihomo_mrs(group_name, group_config, rules)
            
        if 'singbox' in output_directories:
            compile_singbox_srs(global_matrix, output_directories['singbox'])
            
        print("\n[SUCCESS] 所有阶段均已成功执行，具备绝对的事务安全性！")
    except Exception as e:
        print(f"[FATAL ERROR] 阶段 4 提交或编译失败: {e}")
        sys.exit(1)

# 全局入口主函数
def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(async_main())

if __name__ == '__main__':
    main()
