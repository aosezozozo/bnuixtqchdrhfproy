#!/bin/bash

# ProxyIPv6 脚本 - 增强版
# 更新日期: 2025年10月
# 功能: IPv6 代理 + NAT64 支持 + 自动优化

# 颜色定义
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
purple='\033[0;35m'
re='\033[0m'

# 检查是否为 root 用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${red}错误: 此脚本必须以 root 权限运行${re}"
        exit 1
    fi
}

# 显示主菜单
show_menu() {
    clear
    echo -e "${cyan}=====================================${re}"
    echo -e "${cyan}   ProxyIPv6 管理脚本 (增强版)${re}"
    echo -e "${cyan}=====================================${re}"
    echo ""
    echo -e "${green}1.${re} 开启 ProxyIP (IPv6)"
    echo -e "${green}2.${re} 关闭 ProxyIP"
    echo -e "${green}3.${re} 配置 NAT64/DNS64 支持 ${purple}[新]${re}"
    echo -e "${green}4.${re} 查看当前配置状态"
    echo -e "${green}5.${re} 测试 IPv6 连接性"
    echo -e "${green}6.${re} 重置所有配置"
    echo -e "${green}0.${re} 退出脚本"
    echo ""
    echo -e "${cyan}=====================================${re}"
}

# 配置 NAT64
setup_nat64() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}配置 NAT64/DNS64 支持${re}"
    echo -e "${cyan}======================================${re}"
    
    # 最新的 NAT64 提供商列表（2025年10月更新）
    # 格式：提供商名称|DNS64服务器|NAT64前缀
    declare -a nat64_providers=(
        "Kasper Dupont (UK)|2a00:1098:2c::1|2a00:1098:2c:1::"
        "Kasper Dupont (DE-1)|2a01:4f8:c2c:123f::1|2a01:4f8:c2c:123f:64::"
        "level66.services|2a01:4f9:c010:3f02::1|2a01:4f9:c010:3f02:64::"
        "TREX (Finland)|2001:67c:2b0::4|2001:67c:2b0::"
        "TREX (Finland-2)|2001:67c:2b0::6|2001:67c:2b0::"
        "ZTVI (Romania)|2001:67c:2960::6464|2001:67c:2960::"
        "ZTVI (USA)|2602:fc59:b0:9e::64|2602:fc59:b0:9e::"
        "ZTVI (USA-2)|2602:fc59:11:1::64|2602:fc59:11:1::"
    )
    
    echo -e "${yellow}正在测试可用的 NAT64 网关...${re}"
    echo -e "${yellow}将自动选择延迟最低的提供商${re}"
    echo ""
    
    working_provider=""
    working_dns=""
    working_prefix=""
    best_latency=9999
    
    # 测试每个提供商
    for provider_info in "${nat64_providers[@]}"; do
        IFS='|' read -r provider_name dns_server nat64_prefix <<< "$provider_info"
        
        echo -e "${cyan}[测试] ${provider_name}${re}"
        echo -e "  DNS64: ${dns_server}"
        
        # 1. 测试 DNS64 延迟和可用性
        start_time=$(date +%s%3N)
        test_result=$(dig AAAA ipv4only.arpa @${dns_server} +short +time=3 +tries=1 2>/dev/null | head -1)
        end_time=$(date +%s%3N)
        latency=$((end_time - start_time))
        
        if [[ "$test_result" =~ ^64:ff9b:: ]] || [[ "$test_result" =~ ^2[a-f0-9:]+::[a-f0-9:]+ ]]; then
            echo -e "${green}  ✓ DNS64 解析成功 (${latency}ms)${re}"
            
            # 2. 测试实际 TCP 连接（使用合成的 IPv6 地址）
            # 测试 1.1.1.1 (Cloudflare) 转换为 NAT64 地址
            if [[ "$nat64_prefix" == "2001:67c:2b0::" ]]; then
                # TREX 特殊处理：直接用 64:ff9b::
                test_addr="64:ff9b::101:101"
            else
                # 其他提供商：使用他们的前缀
                test_addr="${nat64_prefix}101:101"
            fi
            
            echo -e "  测试连接: ${test_addr}"
            
            if timeout 5 bash -c "cat < /dev/null > /dev/tcp/[${test_addr}]/443" 2>/dev/null; then
                echo -e "${green}  ✓ TCP 443 连接成功！${re}"
                
                # 如果这个提供商延迟更低，使用它
                if [ $latency -lt $best_latency ]; then
                    best_latency=$latency
                    working_provider="$provider_name"
                    working_dns="$dns_server"
                    working_prefix="$nat64_prefix"
                    echo -e "${green}  ★ 当前最佳选择 (${latency}ms)${re}"
                fi
            else
                echo -e "${yellow}  ✗ TCP 连接失败${re}"
            fi
        else
            echo -e "${red}  ✗ DNS64 解析失败或超时${re}"
        fi
        echo ""
    done
    
    if [ -z "$working_provider" ]; then
        echo -e "${red}======================================${re}"
        echo -e "${red}错误：没有找到可用的 NAT64 网关${re}"
        echo -e "${red}======================================${re}"
        echo ""
        echo "所有公共 NAT64 提供商均不可用。"
        echo ""
        echo "可能的原因："
        echo "1. 你的 VPS 提供商屏蔽了外部 NAT64 流量"
        echo "2. 你的 IPv6 路由配置有问题"
        echo "3. 防火墙阻止了 NAT64 连接"
        echo ""
        echo "建议："
        echo "• 检查 IPv6 连接: ping6 google.com"
        echo "• 检查防火墙规则: ip6tables -L"
        echo "• 联系 VPS 提供商确认是否支持 NAT64"
        echo "• 或使用脚本中的纯 IPv6 代理功能"
        echo ""
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    echo -e "${green}======================================${re}"
    echo -e "${green}✓ 找到最佳 NAT64 网关！${re}"
    echo -e "${green}======================================${re}"
    echo -e "提供商: ${working_provider}"
    echo -e "DNS64 服务器: ${working_dns}"
    echo -e "NAT64 前缀: ${working_prefix}"
    echo -e "响应时间: ${best_latency}ms"
    echo ""
    
    # 1. 备份原始 resolv.conf
    if [ ! -f /etc/resolv.conf.backup ]; then
        echo -e "${yellow}备份原始 DNS 配置...${re}"
        cp /etc/resolv.conf /etc/resolv.conf.backup
    fi
    
    # 2. 配置 DNS64 解析器
    echo -e "${yellow}配置 DNS64 解析器...${re}"
    
    # 移除所有旧的 NAT64 配置
    sed -i '/# NAT64/d' /etc/resolv.conf
    sed -i '/2001:67c:2b0::/d' /etc/resolv.conf
    sed -i '/2a01:4f9:c010:3f02::/d' /etc/resolv.conf
    sed -i '/2a01:4f8:c2c:123f::/d' /etc/resolv.conf
    sed -i '/2a00:1098:2c::/d' /etc/resolv.conf
    sed -i '/2001:67c:2960::/d' /etc/resolv.conf
    sed -i '/2602:fc59:/d' /etc/resolv.conf
    
    # 添加新的 DNS64（添加到文件开头）
    sed -i "1i# NAT64/DNS64 - ${working_provider} - $(date '+%Y-%m-%d %H:%M')" /etc/resolv.conf
    sed -i "2i nameserver ${working_dns}" /etc/resolv.conf
    
    echo -e "${green}✓ DNS64 配置完成${re}"
    
    # 3. 配置 NAT64 路由
    echo -e "${yellow}配置 NAT64 路由...${re}"
    
    # 获取默认 IPv6 接口
    default_ipv6_dev=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'dev \K\S+' | head -1)
    
    if [ -z "$default_ipv6_dev" ]; then
        echo -e "${red}✗ 无法检测到 IPv6 网络接口${re}"
        echo "请手动配置 IPv6 路由"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    echo -e "  使用网络接口: ${default_ipv6_dev}"
    
    # 删除旧的 NAT64 路由
    ip -6 route del 64:ff9b::/96 2>/dev/null
    ip -6 route del 2001:67c:2b0::/48 2>/dev/null
    ip -6 route del 2a01:4f9:c010:3f02::/64 2>/dev/null
    ip -6 route del 2a01:4f8:c2c:123f::/64 2>/dev/null
    ip -6 route del 2a00:1098:2c::/48 2>/dev/null
    ip -6 route del 2001:67c:2960::/48 2>/dev/null
    ip -6 route del 2602:fc59::/32 2>/dev/null
    
    # 添加新的 NAT64 路由
    # TREX 使用标准前缀 64:ff9b::/96
    if [[ "$working_prefix" == "2001:67c:2b0::" ]]; then
        ip -6 route add 64:ff9b::/96 dev ${default_ipv6_dev} 2>/dev/null
        if ip -6 route | grep -q "64:ff9b::/96"; then
            echo -e "${green}✓ NAT64 路由配置完成 (64:ff9b::/96)${re}"
        fi
    else
        # 其他提供商使用自定义前缀
        ip -6 route add ${working_prefix}/96 dev ${default_ipv6_dev} 2>/dev/null
        if ip -6 route | grep -q "${working_prefix}"; then
            echo -e "${green}✓ NAT64 路由配置完成 (${working_prefix}/96)${re}"
        fi
    fi
    
    # 4. 持久化配置
    echo -e "${yellow}配置持久化（重启后自动生效）...${re}"
    
    # 创建启动脚本
    cat > /tmp/nat64-setup.sh << EOF
#!/bin/bash
# NAT64 自动配置脚本 - ${working_provider}
# 生成时间: $(date)

sleep 5  # 等待网络就绪

# 获取 IPv6 接口
IPV6_DEV=\$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'dev \K\S+' | head -1)

if [ -n "\$IPV6_DEV" ]; then
    # 删除旧路由
    ip -6 route del 64:ff9b::/96 2>/dev/null
    ip -6 route del 2001:67c:2b0::/48 2>/dev/null
    ip -6 route del 2a01:4f9:c010:3f02::/64 2>/dev/null
    ip -6 route del 2a01:4f8:c2c:123f::/64 2>/dev/null
    ip -6 route del 2a00:1098:2c::/48 2>/dev/null
    ip -6 route del 2001:67c:2960::/48 2>/dev/null
    ip -6 route del 2602:fc59::/32 2>/dev/null
    
    # 添加 NAT64 路由
EOF

    if [[ "$working_prefix" == "2001:67c:2b0::" ]]; then
        echo "    ip -6 route add 64:ff9b::/96 dev \$IPV6_DEV 2>/dev/null" >> /tmp/nat64-setup.sh
    else
        echo "    ip -6 route add ${working_prefix}/96 dev \$IPV6_DEV 2>/dev/null" >> /tmp/nat64-setup.sh
    fi
    
    cat >> /tmp/nat64-setup.sh << EOF
fi

# 恢复 DNS64 配置
if ! grep -q "${working_dns}" /etc/resolv.conf; then
    sed -i "1i nameserver ${working_dns}" /etc/resolv.conf
fi
EOF
    
    mv /tmp/nat64-setup.sh /usr/local/bin/nat64-setup.sh
    chmod +x /usr/local/bin/nat64-setup.sh
    
    # 创建 systemd 服务
    tee /etc/systemd/system/nat64-setup.service > /dev/null << EOF
[Unit]
Description=NAT64 Route Setup (${working_provider})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nat64-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nat64-setup.service 2>/dev/null
    
    echo -e "${green}✓ 持久化配置完成${re}"
    
    # 5. 最终验证
    echo ""
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}验证 NAT64 配置${re}"
    echo -e "${cyan}======================================${re}"
    
    echo -e "${yellow}[1/3] 测试 DNS64 解析...${re}"
    dns_test=$(dig AAAA google.com @${working_dns} +short +time=3 | head -1)
    if [ -n "$dns_test" ]; then
        echo -e "${green}✓ DNS64 解析正常: ${dns_test}${re}"
    else
        echo -e "${red}✗ DNS64 解析失败${re}"
    fi
    
    echo -e "${yellow}[2/3] 测试路由配置...${re}"
    if [[ "$working_prefix" == "2001:67c:2b0::" ]]; then
        route_check="64:ff9b::/96"
    else
        route_check="${working_prefix}"
    fi
    
    if ip -6 route | grep -q "$route_check"; then
        echo -e "${green}✓ NAT64 路由已配置${re}"
    else
        echo -e "${yellow}! NAT64 路由未找到（可能仍可工作）${re}"
    fi
    
    echo -e "${yellow}[3/3] 测试实际连接...${re}"
    if curl -6 -s --max-time 8 -o /dev/null -w "%{http_code}" http://ipv4.google.com 2>/dev/null | grep -q "200\|301\|302"; then
        echo -e "${green}✓ 成功访问 IPv4-only 网站！NAT64 完全可用！${re}"
    elif timeout 5 bash -c "cat < /dev/null > /dev/tcp/[64:ff9b::101:101]/443" 2>/dev/null; then
        echo -e "${green}✓ TCP 连接成功（HTTP可能被限制，但 HTTPS 应该可用）${re}"
    else
        echo -e "${yellow}! 连接测试超时（可能需要几分钟生效，或仅支持特定协议）${re}"
    fi
    
    echo ""
    echo -e "${green}======================================${re}"
    echo -e "${green}NAT64 配置完成！${re}"
    echo -e "${green}======================================${re}"
    echo -e "提供商: ${working_provider}"
    echo -e "DNS64: ${working_dns}"
    echo -e "延迟: ${best_latency}ms"
    echo ""
    echo "配置已持久化，重启后自动生效"
    echo ""
    echo -e "${cyan}提示：${re}"
    echo "• 现在可以返回主菜单开启 ProxyIP"
    echo "• 配置会在 VPS 重启后自动恢复"
    echo "• 如需更换提供商，重新运行此选项即可"
    
    read -p "按回车键返回主菜单..."
}

# 开启 ProxyIP
enable_proxyip() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}开启 ProxyIP (IPv6)${re}"
    echo -e "${cyan}======================================${re}"
    echo ""
    
    # Cloudflare IPv6 地址池
    declare -a ipv6_addresses=(
        "2606:4700:3108::ac42:2ca7"
        "2606:4700:3108::ac42:2ba7"
        "2606:4700:3108::ac42:29a7"
        "2606:4700:3108::ac42:28a7"
    )
    
    echo -e "${yellow}可用的 IPv6 代理地址：${re}"
    echo ""
    
    for i in "${!ipv6_addresses[@]}"; do
        echo -e "${green}$((i+1)).${re} ${ipv6_addresses[$i]} ${cyan}[IPv6]${re}"
    done
    
    echo ""
    echo -e "${yellow}说明：${re}"
    echo "• 这些是 Cloudflare 的真实 IPv6 地址"
    echo "• 如果已配置 NAT64，也可以访问 IPv4 网站"
    echo "• 推荐选择延迟最低的地址"
    echo ""
    
    read -p "请输入要使用的地址编号 (1-${#ipv6_addresses[@]}): " choice
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#ipv6_addresses[@]}" ]; then
        selected_ip="${ipv6_addresses[$((choice-1))]}"
        
        echo ""
        echo -e "${yellow}正在配置 ProxyIP...${re}"
        
        # 配置 warp-cli
        if command -v warp-cli &> /dev/null; then
            warp-cli set-proxy-endpoint "[${selected_ip}]:443"
            echo -e "${green}✓ ProxyIP 已配置: ${selected_ip}${re}"
        else
            echo -e "${yellow}! warp-cli 未安装，仅设置系统代理${re}"
        fi
        
        # 保存配置
        echo "$selected_ip" > /tmp/proxyip_current
        
        echo ""
        echo -e "${green}======================================${re}"
        echo -e "${green}ProxyIP 配置完成！${re}"
        echo -e "${green}======================================${re}"
        echo -e "当前使用: ${selected_ip}"
        
    else
        echo -e "${red}无效的选择！${re}"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# 关闭 ProxyIP
disable_proxyip() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}关闭 ProxyIP${re}"
    echo -e "${cyan}======================================${re}"
    echo ""
    
    if command -v warp-cli &> /dev/null; then
        warp-cli delete-proxy-endpoint
        echo -e "${green}✓ ProxyIP 已关闭${re}"
    fi
    
    rm -f /tmp/proxyip_current
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# 查看当前配置状态
show_status() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}当前配置状态${re}"
    echo -e "${cyan}======================================${re}"
    echo ""
    
    # ProxyIP 状态
    echo -e "${yellow}[ProxyIP 状态]${re}"
    if [ -f /tmp/proxyip_current ]; then
        current_ip=$(cat /tmp/proxyip_current)
        echo -e "${green}✓ 已开启${re}"
        echo -e "  当前地址: ${current_ip}"
    else
        echo -e "${red}✗ 未开启${re}"
    fi
    echo ""
    
    # NAT64 状态
    echo -e "${yellow}[NAT64/DNS64 状态]${re}"
    if ip -6 route | grep -q "64:ff9b::\|2a01:4f9:c010:3f02::\|2a01:4f8:c2c:123f::\|2a00:1098:2c::\|2001:67c:2960::\|2602:fc59::"; then
        echo -e "${green}✓ 已配置${re}"
        
        # 显示 DNS64 服务器
        nat64_dns=$(grep "nameserver 2" /etc/resolv.conf | head -1 | awk '{print $2}')
        if [ -n "$nat64_dns" ]; then
            echo -e "  DNS64: ${nat64_dns}"
        fi
        
        # 显示路由
        nat64_route=$(ip -6 route | grep -E "64:ff9b::|2a01:4f9:c010:3f02::|2a01:4f8:c2c:123f::|2a00:1098:2c::|2001:67c:2960::|2602:fc59::" | head -1)
        if [ -n "$nat64_route" ]; then
            echo -e "  路由: ${nat64_route}"
        fi
    else
        echo -e "${red}✗ 未配置${re}"
    fi
    echo ""
    
    # IPv6 连接测试
    echo -e "${yellow}[IPv6 连接测试]${re}"
    if ping6 -c 1 -W 2 google.com &> /dev/null; then
        echo -e "${green}✓ IPv6 连接正常${re}"
    else
        echo -e "${red}✗ IPv6 连接失败${re}"
    fi
    echo ""
    
    # systemd 服务状态
    echo -e "${yellow}[自动启动服务]${re}"
    if systemctl is-enabled nat64-setup.service &> /dev/null; then
        echo -e "${green}✓ NAT64 自动启动已启用${re}"
    else
        echo -e "${yellow}○ NAT64 自动启动未启用${re}"
    fi
    echo ""
    
    read -p "按回车键返回主菜单..."
}

# 测试 IPv6 连接性
test_ipv6() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}测试 IPv6 连接性${re}"
    echo -e "${cyan}======================================${re}"
    echo ""
    
    echo -e "${yellow}[1/4] 测试 IPv6 基础连接...${re}"
    if ping6 -c 3 -W 2 2001:4860:4860::8888 &> /dev/null; then
        echo -e "${green}✓ IPv6 网络正常 (ping6 Google DNS)${re}"
    else
        echo -e "${red}✗ IPv6 网络异常${re}"
    fi
    echo ""
    
    echo -e "${yellow}[2/4] 测试 DNS 解析...${re}"
    if dig AAAA google.com +short | grep -q "2"; then
        echo -e "${green}✓ DNS 解析正常${re}"
    else
        echo -e "${red}✗ DNS 解析失败${re}"
    fi
    echo ""
    
    echo -e "${yellow}[3/4] 测试 NAT64 解析...${re}"
    nat64_result=$(dig AAAA ipv4only.arpa +short 2>/dev/null | head -1)
    if [ -n "$nat64_result" ]; then
        echo -e "${green}✓ NAT64 DNS64 可用: ${nat64_result}${re}"
    else
        echo -e "${yellow}○ NAT64 DNS64 未配置或不可用${re}"
    fi
    echo ""
    
    echo -e "${yellow}[4/4] 测试 HTTP 连接...${re}"
    if curl -6 -s --max-time 5 -o /dev/null http://ipv6.google.com; then
        echo -e "${green}✓ HTTP over IPv6 正常${re}"
    else
        echo -e "${red}✗ HTTP 连接失败${re}"
    fi
    echo ""
    
    echo -e "${green}======================================${re}"
    echo -e "${green}测试完成${re}"
    echo -e "${green}======================================${re}"
    
    read -p "按回车键返回主菜单..."
}

# 重置所有配置
reset_config() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}重置所有配置${re}"
    echo -e "${cyan}======================================${re}"
    echo ""
    
    echo -e "${red}警告：此操作将清除所有 ProxyIP 和 NAT64 配置！${re}"
    echo ""
    read -p "确定要继续吗？(y/N): " confirm
    
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${yellow}正在重置配置...${re}"
        
        # 关闭 ProxyIP
        if command -v warp-cli &> /dev/null; then
            warp-cli delete-proxy-endpoint 2>/dev/null
        fi
        rm -f /tmp/proxyip_current
        
        # 删除 NAT64 路由
        ip -6 route del 64:ff9b::/96 2>/dev/null
        ip -6 route del 2001:67c:2b0::/48 2>/dev/null
        ip -6 route del 2a01:4f9:c010:3f02::/64 2>/dev/null
        ip -6 route del 2a01:4f8:c2c:123f::/64 2>/dev/null
        ip -6 route del 2a00:1098:2c::/48 2>/dev/null
        ip -6 route del 2001:67c:2960::/48 2>/dev/null
        ip -6 route del 2602:fc59::/32 2>/dev/null
        
        # 恢复 DNS 配置
        if [ -f /etc/resolv.conf.backup ]; then
            cp /etc/resolv.conf.backup /etc/resolv.conf
        fi
        
        # 禁用自动启动服务
        systemctl disable nat64-setup.service 2>/dev/null
        rm -f /etc/systemd/system/nat64-setup.service
        rm -f /usr/local/bin/nat64-setup.sh
        systemctl daemon-reload
        
        echo -e "${green}✓ 所有配置已重置${re}"
    else
        echo -e "${yellow}操作已取消${re}"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# 主程序
main() {
    check_root
    
    while true; 
