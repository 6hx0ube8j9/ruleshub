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
# 2. 🗂️ 统一骨架矩阵 (DRY 原则：单一真理源)
# =========================================================================
ROUTING_MATRIX = {
    # 全局分发平台
    'loon':            {'dir': os.path.join(RULESET_BASE_DIR, 'loon')},
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
# 3. 📂 生命周期管理
# =========================================================================
def setup_environment():
    """
    初始化输出目录，确保所有输出路径物理存在。
    """
    required_dirs = {RULESET_BASE_DIR, SOURCE_DIR, MIHOMO_DIR}
    required_dirs.update(
        cfg['dir'] for cfg in ROUTING_MATRIX.values() if 'dir' in cfg
    )
    for d in sorted(required_dirs):
        os.makedirs(d, exist_ok=True)

# =========================================================================
# 4. ⚙️ 解耦过滤引擎
# =========================================================================
class RuleFilter:
    """
    路由过滤器集合 (静态命名空间类)
    """
    @staticmethod
    def _filter_whitelist(config, name_lower):
        if 'whitelist' not in config: return True
        return any(w.lower() in name_lower for w in config['whitelist'])

    @staticmethod
    def _filter_blacklist(config, name_lower):
        if 'whitelist' in config: return True  # 有白名单时，黑名单失效
        if 'blacklist' not in config: return True
        return not any(b.lower() in name_lower for b in config['blacklist'])

    @staticmethod
    def _filter_regex(config, name_lower):
        if 'regex' not in config: return True
        try:
            return bool(re.search(config['regex'], name_lower, re.IGNORECASE))
        except re.error:
            return False

    _PIPELINE = [_filter_whitelist, _filter_blacklist, _filter_regex]

    @classmethod
    def evaluate(cls, config, group_name_lower):
        return all(filter_func(config, group_name_lower) for filter_func in cls._PIPELINE)

# =========================================================================
# 5. 🔄 自愈规整与内存路由解析核心
# =========================================================================
def _get_normalized_user_value(raw_val):
    """
    清洗用户输入的临时占位符。
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
    - "true" -> 强写为 默认名称（小写）
    - ""     -> 过滤器通过写 默认名称，未通过则强制写为 false 告知关闭
    - 缺失    -> 不处理，走默认内存托管
    """
    with open(json_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)
        
    setup_environment()  # ✨ 修复：这里统一对齐调用 setup_environment()
    modified = False
    
    for group in config_data.get('groups', []):
        group_name = group.get('name')
        outputs = group.get('outputs')
        
        if not group_name or not isinstance(outputs, dict):
            continue
            
        group_name_lower = group_name.lower()
        
        for tool_key, config in ROUTING_MATRIX.items():
            if tool_key not in outputs:
                continue  # 💡 字段直接没有：不作任何发生，保留其干净状态
                
            raw_val = outputs[tool_key]
            user_val = _get_normalized_user_value(raw_val)
            
            # 使用 target_val 状态机收拢面条代码
            target_val = None
            
            if user_val is True:
                target_val = group_name_lower
            elif user_val == '':
                is_passed = RuleFilter.evaluate(config, group_name_lower)
                target_val = group_name_lower if is_passed else False
                
            # 仅在实际发生变更时执行就地修改
            if target_val is not None and raw_val != target_val:
                outputs[tool_key] = target_val
                modified = True

    # 💾 只有发生过自愈，才回写磁盘文件
    if modified:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        print("📝 [配置自愈] 已将 \"true\" 或 \"\" 占位符转换为确定值并写回 JSON！")
        
    return config_data


def resolve_routing(group_config, group_name):
    """
    接口 2：内存路由解析决策引擎。
    """
    group_name_lower = group_name.lower()
    raw_outputs = group_config.get('outputs') or {}
    routing_map = {}
    
    for tool_key, config in ROUTING_MATRIX.items():
        # 1. 字段缺失 -> 走自动托管
        if tool_key not in raw_outputs:
            if RuleFilter.evaluate(config, group_name_lower):
                routing_map[tool_key] = group_name_lower
            continue
            
        # 2. 字段存在 -> 直接提取自愈后的标准值
        user_val = raw_outputs[tool_key]
        if isinstance(user_val, str) and user_val != '':
            routing_map[tool_key] = user_val.lower()
            
    return routing_map


if __name__ == '__main__':
    setup_environment()
    print("Environment setup completed successfully.")
