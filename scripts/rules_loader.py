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

# =========================================================================
# 5. 🛠️ 纯函数与数据流管理 (保持数据不可变性)
# =========================================================================
def _get_normalized_user_value(raw_val):
    """
    即时配置清洗：不修改原数据，仅返回清洗后的期望值。
    """
    if isinstance(raw_val, str):
        val_lower = raw_val.strip().lower()
        if val_lower in ['true', 'ture']: return True
        if val_lower == 'false':          return False
        if val_lower == '':               return ''
        return val_lower 
    return raw_val

# =========================================================================
# 6. 🔌 终极对外接口定义 (Public APIs)
# =========================================================================
def load_and_prepare_config(json_path):
    """
    接口 1：读取并解析 ruleset.json。
    【生命周期守卫】：确保只要外部尝试触碰配置，工作目录就必定百分百就绪。
    """
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"找不到配置文件 ruleset.json: {json_path}")
        
    # 完美的防御式内建触发器
    setup_environment()
        
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"ruleset.json 解析发生语法错误 [{e.lineno}:{e.colno}] -> {e.msg}")

def resolve_routing(group_config, group_name):
    group_name_lower = group_name.lower()
    raw_outputs = group_config.get('outputs') or {}
    
    routing_map = {}
    
    for tool_key, config in ROUTING_MATRIX.items():
        # 1. 提取并清洗用户输入值
        user_val = _get_normalized_user_value(raw_outputs.get(tool_key))
        
        # 2. 强闭状态 -> 内部无声丢弃
        if user_val is False:
            continue
            
        # 3. 强启状态 -> 直接采用默认组名
        if user_val is True:
            routing_map[tool_key] = group_name_lower
            continue
            
        # 4. 自定义名称 -> 雷打不动按自定义小写输出
        if isinstance(user_val, str) and user_val != '':
            routing_map[tool_key] = user_val
            continue
            
        # ---------- 过滤器仲裁阶段 (此时 user_val 仅可能为 '' 或 None) ----------
        is_passed = RuleFilter.evaluate(config, group_name_lower)
        
        # 5. 终审判决
        # 无论是显式留空还是隐式未配：通关了就交差；未通关则直接拦截丢弃，不发生任何事情
        if is_passed:
            routing_map[tool_key] = group_name_lower
            
    return routing_map

# =========================================================================
# 7. 🚀 自动化生命周期守卫 (兼顾独立执行、向下兼容与单测隔离)
# =========================================================================
if __name__ == '__main__':
    # 支持该模块作为一个独立脚本被直接运行进行初始化
    setup_environment()
    print("Environment setup completed successfully.")
