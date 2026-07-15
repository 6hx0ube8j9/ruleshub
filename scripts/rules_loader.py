# -*- coding: utf-8 -*-
import os
import json
import re

# =========================================================================
# 1. 基础路径定义 (纯静态，无副作用)
# =========================================================================
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                  

RULESET_BASE_DIR = os.path.join(PROJECT_ROOT, 'ruleset')
SOURCE_DIR       = os.path.join(SCRIPT_DIR, 'source')
MIHOMO_DIR       = os.path.join(RULESET_BASE_DIR, 'mihomo')

# =========================================================================
# 2. 🗂️ 统一骨架矩阵 (DRY 原则：平台、隧道、输出路径全部收拢，单一真理源)
# =========================================================================
ROUTING_MATRIX = {
    # 全局分发平台
    'loon':             {'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
    'mihomo_classical': {'dir': os.path.join(MIHOMO_DIR, 'classical')},    
    'quantumultx':      {'dir': os.path.join(RULESET_BASE_DIR, 'quantumultx')},    
    'singbox':          {'dir': os.path.join(RULESET_BASE_DIR, 'singbox')},
    'shadowrocket':     {'dir': os.path.join(RULESET_BASE_DIR, 'shadowrocket')},    
    'pac':              {'whitelist': ['direct', 'china'], 'dir': os.path.join(RULESET_BASE_DIR, 'pac')},
    # Mihomo MRS 隧道
    'mihomo_ipcidr':    {'regex': r'(^|[_0-9-])ip([_0-9-]|$)', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'ipcidr')},
    'mihomo_domain':    {'regex': r'^(?!.*(^|[_0-9-])ip([_0-9-]|$)).*$', 'blacklist': ['classic', 'nodomain'], 'dir': os.path.join(MIHOMO_DIR, 'domain')}
}

# =========================================================================
# 3. 📂 生命周期管理 (消除全局隐式 IO)
# =========================================================================
def setup_environment():
    """
    初始化输出目录。由内部守卫或主程序在生命周期中主动调用。
    由于 os.makedirs 具有 exist_ok=True，重复调用零副作用且性能极高。
    """
    # 基础必须目录
    required_dirs = {
        RULESET_BASE_DIR, 
        SOURCE_DIR, 
        MIHOMO_DIR,
    }
    # 从矩阵中动态提取所有配置了输出目录的目标，消除硬编码
    required_dirs.update(
        cfg['dir'] for cfg in ROUTING_MATRIX.values() if 'dir' in cfg
    )
    
    for d in sorted(required_dirs):
        os.makedirs(d, exist_ok=True)

# =========================================================================
# 4. ⚙️ 解耦过滤引擎 (命名空间类封装 - 极度内聚、支持一键折叠)
# =========================================================================
class RuleFilter:
    """
    路由过滤器集合 (静态命名空间类)
    """
    
    @staticmethod
    def _filter_whitelist(config, name_lower):
        """过滤器 1：白名单判定"""
        if 'whitelist' not in config: return True
        # 确保只要有一个白名单词是 name_lower 的子串就通过
        return any(w.lower() in name_lower for w in config['whitelist'])

    @staticmethod
    def _filter_blacklist(config, name_lower):
        """过滤器 2：黑名单判定 (严格遵循黑白排斥铁律)"""
        if 'whitelist' in config: return True  # 有白名单时，黑名单完全失效并被静默忽略
        if 'blacklist' not in config: return True
        
        # 健壮性优化：只要组名 name_lower 包含黑名单里的任意一个词，或者“部分匹配”就直接拉黑
        return not any(b.lower() in name_lower for b in config['blacklist'])

    @staticmethod
    def _filter_regex(config, name_lower):
        """过滤器 3：正则协同判定"""
        if 'regex' not in config: return True
        try:
            # 使用 re.IGNORECASE 忽略大小写，并使用 bool() 明确转换
            return bool(re.search(config['regex'], name_lower, re.IGNORECASE))
        except re.error:
            # 如果正则解析失败，为了安全，默认不通过（返回 False）
            return False

    # 判定管道作为类的内部私有属性收拢，排版极度整洁
    _PIPELINE = [
        _filter_whitelist,
        _filter_blacklist,
        _filter_regex
    ]

    @classmethod
    def evaluate(cls, config, group_name_lower):
        """
        执行链式判定：只有所有注册的过滤器都返回 True（AND 逻辑），才算通过。
        """
        return all(filter_func(config, group_name_lower) for filter_func in cls._PIPELINE)

def _get_normalized_user_value(raw_val):
    """
    清洗用户输入的临时占位符，返回标准统一的类型。
    """
    if isinstance(raw_val, str):
        val_lower = raw_val.strip().lower()
        if val_lower in ['true', 'ture']: return True
        if val_lower == 'false':          return False
        if val_lower == '':               return ''
        return val_lower
    return raw_val


def load_and_prepare_config(json_path):
    """
    接口 1：加载配置并执行【就地自愈规整】。
    - 发现 "true" 占位符：直接强写为 策略组默认名称（小写）
    - 发现 "" 空白占位符：过过滤器写为 默认名称，未过过滤器则写为 false
    - 字段缺失：不触发自愈，继续保持缺省（走内存托管逻辑）
    """
    with open(json_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)
        
    _init_workspace()  # 确保工作目录存在
    modified = False
    
    for group in config_data.get('groups', []):
        group_name = group.get('name')
        outputs = group.get('outputs')
        
        # 严格防御性校验：无组名或 outputs 缺省/非字典时直接跳过
        if not group_name or not isinstance(outputs, dict):
            continue
            
        group_name_lower = group_name.lower()
        
        for tool_key, config in ROUTING_MATRIX.items():
            if tool_key not in outputs:
                continue  # 💡 缺失字段：不作处理，保留原样以维持干净
                
            raw_val = outputs[tool_key]
            user_val = _get_normalized_user_value(raw_val)
            
            # --- 【面条代码收拢核心】通过 target_val 状态机统一收拢判定 ---
            target_val = None
            
            if user_val is True:
                # 强启信号：直接锁定默认名称
                target_val = group_name_lower
                
            elif user_val == '':
                # 留空信号：根据过滤器终审，通过给名称，失败直接物理改写为 false 关闭
                is_passed = RuleFilter.evaluate(config, group_name_lower)
                target_val = group_name_lower if is_passed else False
                
            # 只有在值确实发生改变，且不为 None 时，才触发物理写入，避免无意义的 IO 开销
            if target_val is not None and raw_val != target_val:
                outputs[tool_key] = target_val
                modified = True

    # 💾 只有发生过自愈修改时，才重写 JSON 文件
    if modified:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        print("📝 [配置自愈] 已将 \"true\" 或 \"\" 占位符转换为白纸黑字的确切配置并写回 JSON！")
        
    return config_data


def resolve_routing(group_config, group_name):
    """
    接口 2：内存路由解析决策引擎。
    由于 load_and_prepare_config 已经完成了物理自愈，此处的内存逻辑可以变得极度纯粹。
    """
    group_name_lower = group_name.lower()
    raw_outputs = group_config.get('outputs') or {}
    routing_map = {}
    
    for tool_key, config in ROUTING_MATRIX.items():
        # 1. 字段缺失 -> 启动【自动托管模式】，交由过滤器裁决
        if tool_key not in raw_outputs:
            if RuleFilter.evaluate(config, group_name_lower):
                routing_map[tool_key] = group_name_lower
            continue
            
        # 2. 字段存在 -> 此时配置已被 load_and_prepare_config 自愈规整完毕
        # 此时的内存值只可能是：具体策略组名称(str) 或 已关闭(False)
        user_val = raw_outputs[tool_key]
        
        # 如果是合法的非空字符串，直接输出（确保万无一失转为小写）
        if isinstance(user_val, str) and user_val != '':
            routing_map[tool_key] = user_val.lower()
            
    return routing_map

# =========================================================================
# 7. 🚀 自动化生命周期守卫 (兼顾独立执行、向下兼容与单测隔离)
# =========================================================================
if __name__ == '__main__':
    # 支持该模块作为一个独立脚本被直接运行进行初始化
    setup_environment()
    print("Environment setup completed successfully.")
