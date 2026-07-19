# -*- coding: utf-8 -*-
import os
import json


# ---------------- 阶段 1: 辅助文本构建工具 ----------------

def mihomo_ipcidr_text(rules):
    """构建供 Mihomo 编译 MRS 二进制文件的纯 IP 类格式 YAML 文本。"""
    combined_ips = sorted(rules.get('ip', set()) | rules.get('ip6', set()))
    if not combined_ips:
        print("[信息] 未检测到有效的 IP 规则条目，跳过文本构建")
        return ""
        
    indent = " " * 4
    payload = ["payload:"]
    payload.extend(f"{indent}- {item}" for item in combined_ips)  
    return "\n".join(payload) + "\n"

def mihomo_domain_text(rules):
    """构建供 Mihomo 编译 MRS 二进制文件的纯域名类格式 YAML 文本。"""
    full_set = rules.get('full', set())
    suffix_set = rules.get('suffix', set())
    if not full_set and not suffix_set:
        print("[信息] 未检测到有效的域名规则条目，跳过文本构建")
        return ""
        
    indent = " " * 4
    payload = ["payload:"]
    payload.extend(f"{indent}- {item}" for item in sorted(full_set))
    payload.extend(f"{indent}- +.{item}" for item in sorted(suffix_set))        
    return "\n".join(payload) + "\n"


# ---------------- 阶段 2: 核心调度与路由 ----------------

def export_all(global_matrix, dir_map):
    """统一调度并导出所有平台的规则集文件（动态映射驱动）。"""
    print("[信息] 开始启动多平台规则集统一导出流程")
    for plat, output_dir in dir_map.items():
        print(f"[信息] 正在检索平台配置分支: {plat}")
        if plat in global_matrix:
            generator_func = globals().get(f"generate_{plat}")
            if generator_func:
                print(f"[信息] 成功映射平台生成函数，准备调用: generate_{plat}")
                generator_func(global_matrix[plat], output_dir)
            else:
                print(f"[警告] 找不到该平台的生成函数: {plat}")


# ---------------- 阶段 3: 平台规则集生成器 ----------------

def generate_mihomo_classical(matrix_data, output_dir):
    """生成 Mihomo Classical 格式的 YAML 规则集。"""
    for g_name, g_rules in matrix_data.items():
        mihomo_path = os.path.join(output_dir, f"{g_name}.yaml")
        lines = [f"# Mihomo Payload Rule-Set: {g_name}\npayload:\n"]
        
        # 定义 Mihomo 规则类型的写入顺序与映射关系
        ordered_types = [
            ('PROCESS-NAME', 'process'), ('DST-PORT', 'port'), ('DOMAIN', 'full'),
            ('DOMAIN-SUFFIX', 'suffix'), ('DOMAIN-KEYWORD', 'keyword'),
            ('IP-CIDR', 'ip'), ('IP-CIDR6', 'ip6'), ('DOMAIN-WILDCARD', 'wildcard'), ('DOMAIN-REGEX', 'regex')
        ]
        for raw_type, ik in ordered_types:
            for val in sorted(g_rules.get(ik, [])):
                if ik in ['ip', 'ip6']: 
                    lines.append(f"  - {raw_type},{val},no-resolve\n")
                else: 
                    lines.append(f"  - {raw_type},{val}\n")

        print(f"[信息] 开始写入 Mihomo Classical 规则集文件: {mihomo_path}")
        with open(mihomo_path, 'w', encoding='utf-8') as f:
            f.write("".join(lines))
        print(f"[成功] Mihomo Classical 规则集文件写入完成: {mihomo_path}")

def generate_quantumultx(matrix_data, output_dir):
    """生成 Quantumult X 格式的规则集文件 (.list)。"""
    for g_name, g_rules in matrix_data.items():
        qx_path = os.path.join(output_dir, f"{g_name}.list")
        qx_policy = g_rules.get('policy_label', 'DIRECT')
        
        lines = [f"# Quantumult X Rule-Set: {g_name}\n\n"]
        # 写入标准前缀与 IP 类型
        qx_ordered_types = [
            ('host', 'full'), ('host-suffix', 'suffix'), ('host-keyword', 'keyword'),
            ('ip-cidr', 'ip'), ('ip6-cidr', 'ip6')
        ]
        for qx_prefix, ik in qx_ordered_types:
            for val in sorted(g_rules.get(ik, [])):
                if 'ip' in ik: 
                    lines.append(f"{qx_prefix}, {val}, {qx_policy}, no-resolve\n")
                else: 
                    lines.append(f"{qx_prefix}, {val}, {qx_policy}\n")

        # 写入 User-Agent 匹配逻辑（含特殊字符包裹处理）
        for val in sorted(g_rules.get('useragent', [])):
            qx_ua = f"*{val}*" if not ('*' in val or '?' in val) else val
            if ',' in qx_ua: qx_ua = f'"{qx_ua}"'
            lines.append(f"user-agent, {qx_ua}, {qx_policy}\n")
        
        # 写入通配符与正则规则
        for val in sorted(g_rules.get('wildcard', [])): 
            lines.append(f"host-wildcard, {val}, {qx_policy}\n")
        for val in sorted(g_rules.get('regex', [])): 
            lines.append(f"host-regex, {val.strip()}, {qx_policy}\n")

        print(f"[信息] 开始写入 Quantumult X 规则集文件: {qx_path}")
        with open(qx_path, 'w', encoding='utf-8') as f:
            f.write("".join(lines))
        print(f"[成功] Quantumult X 规则集文件写入完成: {qx_path}")

def generate_shadowrocket(matrix_data, output_dir):
    """生成 Shadowrocket 格式的规则集文件 (.list)。"""
    for g_name, g_rules in matrix_data.items():
        sr_path = os.path.join(output_dir, f"{g_name}.list")
        
        lines = [f"# Shadowrocket Rule-Set: {g_name}\n\n"]
        # 过滤并单独处理端口规则
        for val in sorted({str(p) for p in g_rules.get('port', [])}):
            if '-' in val or ':' in val: continue
            lines.append(f"DST-PORT,{val}\n")

        # 顺序映射并写入域名、IP、UA 及高级规则类型
        sr_ordered_types = [
            ('DOMAIN', 'full'), ('DOMAIN-SUFFIX', 'suffix'), ('DOMAIN-KEYWORD', 'keyword'),
            ('IP-CIDR', 'ip'), ('IP-CIDR6', 'ip6'), ('USER-AGENT', 'useragent'),
            ('DOMAIN-WILDCARD', 'wildcard'), ('DOMAIN-REGEX', 'regex')
        ]
        for raw_type, ik in sr_ordered_types:
            for val in sorted(g_rules.get(ik, [])):
                if ik in ['ip', 'ip6']: 
                    lines.append(f"{raw_type},{val},no-resolve\n")
                else: 
                    lines.append(f"{raw_type},{val}\n")

        print(f"[信息] 开始写入 Shadowrocket 规则集文件: {sr_path}")
        with open(sr_path, 'w', encoding='utf-8') as f:
            f.write("".join(lines))
        print(f"[成功] Shadowrocket 规则集文件写入完成: {sr_path}")

def generate_loon(matrix_data, output_dir):
    """生成 Loon 格式的规则集文件 (.lsr)。"""
    for g_name, g_rules in matrix_data.items():
        loon_path = os.path.join(output_dir, f"{g_name}.lsr")
        
        lines = [f"# Loon Rule-Set: {g_name}\n\n"]
        # 合并 IPv4 和 IPv6 规则集合
        combined_loon_ips = set(g_rules.get('ip', set()) | g_rules.get('ip6', set()))

        # 构建渲染管线统一格式化输出
        loon_rendering_pipeline = [   
            ('DOMAIN', g_rules.get('full', set())),
            ('DOMAIN-SUFFIX', g_rules.get('suffix', set())),
            ('DOMAIN-KEYWORD', g_rules.get('keyword', set())),        
            ('IP-CIDR', combined_loon_ips),
            ('USER-AGENT', g_rules.get('useragent', set()))
        ]
        for loon_tag, rule_set in loon_rendering_pipeline:
            if rule_set:
                for val in sorted(rule_set):
                    if loon_tag == 'IP-CIDR':
                        lines.append(f"IP-CIDR,{val},no-resolve\n")
                    else:
                        lines.append(f"{loon_tag},{val}\n")

        print(f"[信息] 开始写入 Loon 规则集文件: {loon_path}")
        with open(loon_path, 'w', encoding='utf-8') as f:
            f.write("".join(lines))
        print(f"[成功] LSR 规则集生成成功: {g_name}.lsr")

def generate_singbox(matrix_data, output_dir):
    """生成 Sing-box 格式的 JSON 规则集文件。"""
    for g_name, raw_rules in matrix_data.items():
        sb_path = os.path.join(output_dir, f"{g_name}.json")
        g_rules = {k: list(v) if isinstance(v, (list, set, tuple)) else v for k, v in raw_rules.items()}

        sb_data = {"version": 2, "rules": []}
        dest_rule = {}
        
        # 组装各类基础域名断言
        if g_rules.get('full'):           dest_rule["domain"] = sorted(list(g_rules['full']))
        if g_rules.get('suffix'):         dest_rule["domain_suffix"] = sorted(list(g_rules['suffix']))
        if g_rules.get('keyword'):        dest_rule["domain_keyword"] = sorted(list(g_rules['keyword']))
        if g_rules.get('regex'):          dest_rule["domain_regex"] = sorted(list(set(g_rules['regex'])))
            
        # 提取并合并 IP CIDR 条目
        combined_ips = sorted(set(g_rules.get('ip', [])) | set(g_rules.get('ip6', [])))
        if combined_ips:                  dest_rule["ip_cidr"] = combined_ips

        if dest_rule:
            sb_data["rules"].append(dest_rule)
            
        # 提取进程名（剔除路径与 Windows 后缀）
        if g_rules.get('process'):
            proc_set = {os.path.basename(p.replace('\\', '/'))[:-4] if p.replace('\\', '/').lower().endswith('.exe') 
                        else os.path.basename(p.replace('\\', '/')) for p in g_rules['process'] if p}
            if proc_set:
                sb_data["rules"].append({"process_name": sorted(list(proc_set))})

        # 附带追加逻辑与条件规则
        if g_rules.get('logical_and'):
            for and_rule in g_rules['logical_and']:
                sb_data["rules"].append(and_rule)

        # 100% 保证写盘，不漏掉任何文件
        print(f"[信息] 开始写入 Sing-box 规则集文件: {sb_path}")
        with open(sb_path, 'w', encoding='utf-8') as f:
            json.dump(sb_data, f, indent=2, ensure_ascii=False)
        print(f"[成功] Sing-box 规则集文件写入完成: {sb_path}")

def generate_pac(matrix_data, output_dir):
    """生成标准 Proxy Auto-Config (PAC) 脚本文件 (.pac)。"""
    for g_name, g_rules in matrix_data.items():
        pac_path = os.path.join(output_dir, f"{g_name}.pac")
        combined_domains = set(g_rules.get('suffix', [])) | set(g_rules.get('full', []))
        direct_domains = sorted(combined_domains)
        
        lines = []
        lines.append("var IP_ADDRESS = '127.0.0.1:7891';\n")
        lines.append("var PROXY_METHOD = 'SOCKS5 ' + IP_ADDRESS + '; SOCKS ' + IP_ADDRESS + '; DIRECT';\n\n")
        lines.append("var DIRECT_DOMAINS = {\n")
        for i, domain in enumerate(direct_domains):
            comma = "," if i < len(direct_domains) - 1 else ""
            lines.append(f'    "{domain}": 1{comma}\n')
        lines.append("};\n\n")
        
        # 核心内置 PAC 过滤逻辑 JS 脚本
        js_function = """var PRIVATE_IP_REGEXP = /^(127|10|192\\.168|172\\.(1[6-9]|2[0-9]|3[01]))\\./;
var IS_IPV4_REGEXP = /^\\d+\\.\\d+\\.\\d+\\.\\d+$/;
var IS_IPV6_REGEXP = /^\\[.*\\]$/;

function FindProxyForURL(url, host) {
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    if (IS_IPV4_REGEXP.test(host)) {
        if (PRIVATE_IP_REGEXP.test(host)) return "DIRECT"; 
    } else if (IS_IPV6_REGEXP.test(host)) {
        if (host === "[::1]" || host.indexOf("[fe80") === 0) return "DIRECT"; 
    }

    var suffix = host.toLowerCase();
    while (suffix) {
        if (DIRECT_DOMAINS.hasOwnProperty(suffix)) {
            return "DIRECT";
        }
        var pos = suffix.indexOf('.');
        if (pos === -1) break;
        suffix = suffix.substring(pos + 1);
    }

    return PROXY_METHOD;
}
"""
        lines.append(js_function)
        print(f"[信息] 开始写入 PAC 脚本文件: {pac_path}")
        with open(pac_path, 'w', encoding='utf-8') as f:
            f.write("".join(lines))
        print(f"[成功] PAC 脚本文件写入完成: {pac_path}")
