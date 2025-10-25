#!/bin/bash
export LANG=en_US.UTF-8
# 定义颜色
re='\e[0m'
red='\e[1;91m'
white='\e[1;97m'
green='\e[1;32m'
yellow='\e[1;33m'
purple='\e[1;35m'
skyblue='\e[1;96m'
cyan='\e[1;36m'

# 检查是否有参数以启用无交互模式并作为端口号
NON_INTERACTIVE=0
PORT_PARAM=""
if [ -n "$1" ]; then
    NON_INTERACTIVE=1
    PORT_PARAM="$1"
fi

# 定义IPv6地址的正则表达式
ipv6_regex="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9]))$"

# 等待用户返回
break_end() {
    echo -e "${green}执行完成${re}"
    echo -e "${yellow}按任意键返回...${re}"
    read -n 1 -s -r -p ""
    echo ""
    clear
}

# 安装依赖包
install() {
    if [ $# -eq 0 ]; then
        echo -e "${red}未提供软件包参数!${re}"
        return 1
    fi

    for package in "$@"; do
        if command -v "$package" &>/dev/null; then
            echo -e "${green}${package}已经安装了！${re}"
            continue
        fi
        echo -e "${yellow}正在安装 ${package}...${re}"
        
        if [ "$package" == "dig" ]; then
            if command -v apt &>/dev/null; then
                package="dnsutils"
            elif command -v dnf &>/dev/null; then
                package="bind-utils"
            elif command -v yum &>/dev/null; then
                package="bind-utils"
            elif command -v apk &>/dev/null; then
                package="bind-tools"
            fi
        fi

        if command -v apt &>/dev/null; then
            apt install -y "$package"
        elif command -v dnf &>/dev/null; then
            dnf install -y "$package"
        elif command -v yum &>/dev/null; then
            yum install -y "$package"
        elif command -v apk &>/dev/null; then
            apk add "$package"
        else
            echo -e "${red}暂不支持你的系统!${re}"
            return 1
        fi
    done

    return 0
}

# 简化版 NAT64/DNS64 配置
setup_nat64() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}配置 NAT64/DNS64 支持${re}"
    echo -e "${cyan}======================================${re}"
    echo ""
    echo -e "${yellow}什么是 NAT64/DNS64?${re}"
    echo "• 让纯 IPv6 VPS 可以访问 IPv4-only 的网站"
    echo "• 例如：访问只有 IPv4 的 GitHub、Google 等"
    echo "• 通过 DNS64 自动将 IPv4 地址转换为 IPv6"
    echo ""
    
    # DNS64 服务器列表（2025年最新）
    declare -a dns64_servers=(
        "Level66 Primary (推荐)|2001:67c:2960::64"
        "Level66 Secondary|2001:67c:2960::6464"
        "TREX Finland-1|2001:67c:2b0::4"
        "TREX Finland-2|2001:67c:2b0::6"
        "Kasper UK|2a00:1098:2c::1"
        "Kasper DE|2a01:4f8:c2c:123f::1"
    )
    
    echo -e "${yellow}正在测试可用的 DNS64 服务器...${re}"
    echo ""
    
    best_dns=""
    best_name=""
    best_latency=9999
    
    for server_info in "${dns64_servers[@]}"; do
        IFS='|' read -r name dns <<< "$server_info"
        
        echo -e "${cyan}[测试] ${name}${re}"
        echo -e "  DNS64: ${dns}"
        
        # 测试 DNS64 解析速度
        start=$(date +%s%3N)
        result=$(dig AAAA ipv4only.arpa @${dns} +short +time=3 +tries=1 2>/dev/null | head -1)
        end=$(date +%s%3N)
        latency=$((end - start))
        
        # 检查解析是否成功（返回的应该是 64:ff9b:: 或其他 NAT64 前缀）
        if [[ -n "$result" ]] && [[ "$result" =~ ^[0-9a-f:]+$ ]]; then
            echo -e "${green}  ✓ DNS64 解析成功 (${latency}ms)${re}"
            echo -e "    返回: ${result}"
            
            # 测试实际连接（访问 IPv4-only 网站）
            echo -e "  测试访问 IPv4-only 网站..."
            if timeout 8 curl -6 --dns-servers ${dns} -s -o /dev/null -w "%{http_code}" "http://ipv4.google.com" 2>/dev/null | grep -q "200\|301\|302"; then
                echo -e "${green}  ✓ 成功访问 IPv4-only 网站！${re}"
                
                if [ $latency -lt $best_latency ]; then
                    best_latency=$latency
                    best_dns="$dns"
                    best_name="$name"
                    echo -e "${green}  ★ 当前最佳选择${re}"
                fi
            else
                echo -e "${yellow}  ! 访问测试未通过（DNS 可用但连接受限）${re}"
            fi
        else
            echo -e "${red}  ✗ DNS64 解析失败${re}"
        fi
        echo ""
    done
    
    if [ -z "$best_dns" ]; then
        echo -e "${red}======================================${re}"
        echo -e "${red}错误：没有找到可用的 DNS64 服务器${re}"
        echo -e "${red}======================================${re}"
        echo ""
        echo "可能的原因："
        echo "1. 你的 VPS 提供商屏蔽了 NAT64 流量"
        echo "2. IPv6 网络配置有问题"
        echo "3. 防火墙阻止了相关连接"
        echo ""
        echo "建议："
        echo "• 检查 IPv6 连接: ping6 google.com"
        echo "• 检查 DNS: dig AAAA google.com @2001:67c:2960::64"
        echo "• 联系 VPS 提供商确认是否支持 NAT64"
        echo ""
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    echo -e "${green}======================================${re}"
    echo -e "${green}✓ 找到最佳 DNS64 服务器！${re}"
    echo -e "${green}======================================${re}"
    echo -e "提供商: ${best_name}"
    echo -e "DNS64 服务器: ${best_dns}"
    echo -e "响应时间: ${best_latency}ms"
    echo ""
    
    # 备份原始 DNS 配置
    if [ ! -f /etc/resolv.conf.backup ]; then
        echo -e "${yellow}备份原始 DNS 配置...${re}"
        cp /etc/resolv.conf /etc/resolv.conf.backup
    fi
    
    # 清理旧的 NAT64 DNS 配置
    echo -e "${yellow}清理旧配置...${re}"
    sed -i '/# NAT64/d' /etc/resolv.conf
    sed -i '/2001:67c:2960::/d' /etc/resolv.conf
    sed -i '/2001:67c:2b0::/d' /etc/resolv.conf
    sed -i '/2a00:1098:2c::/d' /etc/resolv.conf
    sed -i '/2a01:4f8:c2c:123f::/d' /etc/resolv.conf
    
    # 添加新的 DNS64 配置
    echo -e "${yellow}配置 DNS64...${re}"
    sed -i "1i# NAT64/DNS64 - ${best_name} - $(date '+%Y-%m-%d %H:%M')" /etc/resolv.conf
    sed -i "2inameserver ${best_dns}" /etc/resolv.conf
    
    echo -e "${green}✓ DNS64 配置完成${re}"
    
    # 持久化配置（重启后自动生效）
    echo -e "${yellow}配置持久化...${re}"
    
    cat > /tmp/dns64-setup.sh << EOF
#!/bin/bash
# DNS64 自动配置脚本 - ${best_name}
# 生成时间: $(date)

# 等待网络就绪
sleep 3

# 恢复 DNS64 配置
if ! grep -q "${best_dns}" /etc/resolv.conf; then
    sed -i "1i# NAT64/DNS64 - ${best_name}" /etc/resolv.conf
    sed -i "2inameserver ${best_dns}" /etc/resolv.conf
fi
EOF
    
    mv /tmp/dns64-setup.sh /usr/local/bin/dns64-setup.sh
    chmod +x /usr/local/bin/dns64-setup.sh
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/dns64-setup.service << EOF
[Unit]
Description=DNS64 Setup (${best_name})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dns64-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable dns64-setup.service 2>/dev/null
    
    echo -e "${green}✓ 持久化配置完成${re}"
    
    # 最终验证
    echo ""
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}验证 NAT64 配置${re}"
    echo -e "${cyan}======================================${re}"
    
    echo -e "${yellow}[1/2] 测试 DNS64 解析...${re}"
    test_result=$(dig AAAA google.com @${best_dns} +short +time=3 | head -1)
    if [ -n "$test_result" ]; then
        echo -e "${green}✓ DNS64 解析正常${re}"
        echo -e "  google.com → ${test_result}"
    else
        echo -e "${yellow}! DNS64 解析未返回结果（可能需要等待）${re}"
    fi
    
    echo -e "${yellow}[2/2] 测试实际连接...${re}"
    if timeout 8 curl -6 -s --max-time 5 -o /dev/null -w "%{http_code}" "http://ipv4.google.com" 2>/dev/null | grep -q "200\|301\|302"; then
        echo -e "${green}✓ 成功访问 IPv4-only 网站！NAT64 完全可用！${re}"
    else
        echo -e "${yellow}! 连接测试超时${re}"
        echo -e "${yellow}  提示：有时需要等待 1-2 分钟才能完全生效${re}"
    fi
    
    echo ""
    echo -e "${green}======================================${re}"
    echo -e "${green}NAT64 配置完成！${re}"
    echo -e "${green}======================================${re}"
    echo -e "提供商: ${best_name}"
    echo -e "DNS64: ${best_dns}"
    echo -e "延迟: ${best_latency}ms"
    echo ""
    echo -e "${cyan}重要提示：${re}"
    echo "• 配置已持久化，重启后自动生效"
    echo "• 现在可以返回主菜单开启 ProxyIP"
    echo "• 你的 VPS 现在可以访问 IPv4-only 网站了！"
    echo ""
    
    read -p "按回车键返回主菜单..."
}

# 获取 Cloudflare CDN 的 IPv6 地址
cf2ipv6s() {
    local domain
    cf_ipv6s=()
    
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}获取 Cloudflare CDN 地址${re}"
    echo -e "${cyan}======================================${re}"
    
    for domain in "$@"; do
        echo -e "${yellow}查询域名: ${domain}${re}"
        
        # 优先使用 DNS64 服务器（如果已配置）
        dns_server=$(grep "nameserver 2001:67c:2960::" /etc/resolv.conf | head -1 | awk '{print $2}')
        if [ -z "$dns_server" ]; then
            dns_server="2606:4700:4700::1111"  # Cloudflare DNS 备用
        fi
        
        # 查询 AAAA 记录
        echo -e "${cyan}  查询 IPv6 地址...${re}"
        ipv6s=($(dig AAAA "$domain" @${dns_server} +short 2>/dev/null | grep -E "$ipv6_regex"))
        
        if [ ${#ipv6s[@]} -gt 0 ]; then
            echo -e "${green}  ✓ 找到 ${#ipv6s[@]} 个地址${re}"
            for ipv6 in "${ipv6s[@]}"; do
                cf_ipv6s+=("$ipv6")
                echo -e "    - ${ipv6}"
            done
        else
            echo -e "${yellow}  ! 未找到 IPv6 地址${re}"
        fi
        echo ""
    done
    
    # 如果没有找到任何地址，尝试使用备用域名
    if [ ${#cf_ipv6s[@]} -eq 0 ]; then
        echo -e "${yellow}使用备用 Cloudflare 地址...${re}"
        # 这些是 Cloudflare 的固定 IPv6 地址
        cf_ipv6s=(
            "2606:4700::6810:85e5"
            "2606:4700::6810:84e5"
            "2606:4700:3034::6815:4c80"
        )
    fi
}

del_ip6tables() {
    echo -e "${yellow}清理旧的 ip6tables 规则...${re}"
    
    # 清空 NAT 表
    ip6tables -t nat -F PREROUTING 2>/dev/null
    ip6tables -t nat -F POSTROUTING 2>/dev/null
    
    echo -e "${green}✓ 规则已清理${re}"
}

get_ipv6() {
    echo -e "${yellow}获取当前服务器 IPv6 地址...${re}"
    
    # 尝试多个 API 获取 IPv6
    ipv6_address=$(curl -6 -s --max-time 3 ipv6.ip.sb 2>/dev/null)
    
    if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
        ipv6_address=$(curl -6 -s --max-time 3 ipv6.ping0.cc 2>/dev/null)
    fi
    
    if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
        ipv6_address=$(ip -6 addr show scope global | grep -oP '(?<=inet6\s)[\da-f:]+' | head -1)
    fi
    
    if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
        echo -e "${red}无法获取 IPv6 地址${re}"
        read -p "是否继续（不推荐）? (Y/N): " continue_anyway
        if [[ "${continue_anyway^^}" != "Y" ]]; then
            exit 1
        fi
        ipv6_address="无效地址"
    fi

    # 生成 ProxyIP 域名格式
    ipv6_domain="priv.$(echo $ipv6_address | sed 's/:/-/g').ip.proy.pp.ua"

    echo -e "当前服务器 IPv6: ${green}[${ipv6_address}]${re}"
}

start() {
    local non_interactive=${1:-0}
    
    get_ipv6

    # 安装依赖
    if [ $non_interactive -eq 1 ]; then
        echo -e "${yellow}自动安装依赖包...${re}"
        install sudo curl dig
    else
        echo -e "脚本所需依赖: ${yellow}curl, sudo, dig${re}"
        read -p "是否允许脚本自动安装依赖? (Y/N 默认Y): " install_apps
        install_apps=${install_apps^^}
        install_apps=${install_apps:-Y}
        if [ "$install_apps" == "Y" ]; then
            install sudo curl dig
        fi
    fi

    # 启用 IPv6 转发
    echo -e "${yellow}启用 IPv6 流量转发...${re}"
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null 2>&1
    echo -e "${green}✓ IPv6 转发已启用${re}"

    # 询问是否配置 NAT64
    if [ $non_interactive -eq 0 ]; then
        echo ""
        echo -e "${cyan}======================================${re}"
        echo -e "${cyan}关于 NAT64${re}"
        echo -e "${cyan}======================================${re}"
        echo -e "${yellow}NAT64 让你的纯 IPv6 VPS 可以：${re}"
        echo "• 访问 IPv4-only 的 Cloudflare 网站"
        echo "• 扩展可用的 ProxyIP 地址池"
        echo "• 提高连接成功率"
        echo ""
        read -p "是否配置 NAT64 支持? (Y/N 默认Y): " enable_nat64
        enable_nat64=${enable_nat64^^}
        enable_nat64=${enable_nat64:-Y}
        
        if [ "$enable_nat64" == "Y" ]; then
            setup_nat64
        fi
    else
        setup_nat64
    fi

    # 获取 Cloudflare 地址
    echo ""
    cf2ipv6s ip.sb time.is cloudflare.com

    if [ ${#cf_ipv6s[@]} -eq 0 ]; then
        echo -e "${red}未找到任何可用地址，退出${re}"
        exit 1
    fi

    # 显示可用地址
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}可用的 Cloudflare CDN 地址${re}"
    echo -e "${cyan}======================================${re}"
    
    for i in "${!cf_ipv6s[@]}"; do
        printf "${yellow}[%2d]${re} ${green}%s${re}\n" "$((i+1))" "${cf_ipv6s[$i]}"
    done
    echo -e "${cyan}======================================${re}"

    # 选择地址
    if [ $non_interactive -eq 1 ]; then
        random_ipv6="${cf_ipv6s[0]}"  # 无交互模式使用第一个
    else
        while true; do
            read -p "请选择地址编号 (1-${#cf_ipv6s[@]}, 0=随机): " choice
            choice=${choice:-0}
            
            if [ "$choice" == "0" ]; then
                random_ipv6="${cf_ipv6s[$((RANDOM % ${#cf_ipv6s[@]}))]}"
                echo -e "${green}随机选择: ${random_ipv6}${re}"
                break
            elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#cf_ipv6s[@]}" ]; then
                random_ipv6="${cf_ipv6s[$((choice-1))]}"
                echo -e "${green}已选择: ${random_ipv6}${re}"
                break
            else
                echo -e "${red}无效选择！${re}"
            fi
        done
    fi

    # 配置端口
    if [ $non_interactive -eq 1 ]; then
        local_port=$PORT_PARAM
    else
        read -p "请输入本地端口 (默认 443): " local_port
        local_port=${local_port:-443}
    fi
    
    # 检查端口占用
    if ss -tuln | grep -q ":${local_port} "; then
        echo -e "${red}端口 ${local_port} 已被占用！${re}"
        exit 1
    fi

    # 清理旧规则
    del_ip6tables

    # 添加转发规则
    echo -e "${yellow}配置端口转发规则...${re}"
    ip6tables -t nat -A PREROUTING -p tcp --dport $local_port -j DNAT --to-destination [${random_ipv6}]:443
    ip6tables -t nat -A POSTROUTING -j MASQUERADE
    echo -e "${green}✓ 转发规则已添加${re}"

    # 保存规则
    echo -e "${yellow}保存 ip6tables 规则...${re}"
    mkdir -p /etc/iptables
    ip6tables-save > /etc/iptables/rules.v6
    
    # 持久化规则
    if [ -d "/etc/network/if-pre-up.d" ]; then
        cat > /etc/network/if-pre-up.d/ip6tables << 'EOF'
#!/bin/sh
[ -f /etc/iptables/rules.v6 ] && ip6tables-restore < /etc/iptables/rules.v6
exit 0
EOF
        chmod +x /etc/network/if-pre-up.d/ip6tables
    else
        cat > /etc/systemd/system/ip6tables-restore.service << 'EOF'
[Unit]
Description=Restore ip6tables rules
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ip6tables-restore.service 2>/dev/null
    fi
    
    echo -e "${green}✓ 规则持久化完成${re}"
}

# 清除 NAT64 配置
remove_nat64() {
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}清除 NAT64 配置${re}"
    echo -e "${cyan}======================================${re}"
    
    if [ -f /etc/resolv.conf.backup ]; then
        mv /etc/resolv.conf.backup /etc/resolv.conf
        echo -e "${green}✓ 已恢复原 DNS 配置${re}"
    else
        sed -i '/# NAT64/d' /etc/resolv.conf
        sed -i '/2001:67c:2960::/d' /etc/resolv.conf
        sed -i '/2001:67c:2b0::/d' /etc/resolv.conf
        sed -i '/2a00:1098:2c::/d' /etc/resolv.conf
        sed -i '/2a01:4f8:c2c:123f::/d' /etc/resolv.conf
        echo -e "${green}✓ 已移除 NAT64 DNS${re}"
    fi
    
    if [ -f /usr/local/bin/dns64-setup.sh ]; then
        rm /usr/local/bin/dns64-setup.sh
    fi
    
    if [ -f /etc/systemd/system/dns64-setup.service ]; then
        systemctl disable dns64-setup.service 2>/dev/null
        rm /etc/systemd/system/dns64-setup.service
        systemctl daemon-reload
    fi
    
    echo -e "${green}NAT64 配置已清除${re}"
    read -p "按回车键继续..."
}

# 主菜单
if [ $NON_INTERACTIVE -eq 1 ]; then
    echo "无交互模式，自动开启 ProxyIP..."
    start 1
    echo -e "${green}======================================${re}"
    echo -e "${green}ProxyIP 开启成功！${re}"
    echo -e "${green}======================================${re}"
    echo -e "端口: ${yellow}${PORT_PARAM}${re}"
    echo -e "域名: ${green}${ipv6_domain}${re}"
    exit 0
fi

while true; do
    get_ipv6
    clear
    
    echo -e "${yellow} ____                      ___ ____         __   ${re}"
    echo -e "${yellow}|  _ \\ _ __ _____  ___   _|_ _|  _ \\__   __/ /_  ${re}"
    echo -e "${yellow}| |_) | '__/ _ \\ \\/ / | | || || |_) \\ \\ / / '_ \\ ${re}"
    echo -e "${yellow}|  __/| | | (_) >  <| |_| || ||  __/ \\ V /| (_) |${re}"
    echo -e "${yellow}|_|   |_|  \\___/_/\\_\\\\__,  |___|_|     \\_/  \\___/ ${re}"
    echo -e " 作者: cmliu         ${yellow}|___/${re}"
    echo -e " ${cyan}简化版: 更稳定的 NAT64 支持${re}"
    echo "-------------------------------------------------------------------"
    echo " 配置信息:" 
    echo -e " IPv6: ${green}[${ipv6_address}]${re}"
    echo -e " ProxyIP: ${green}${ipv6_domain}${re}"
    
    # 检查 NAT64 状态
    if grep -q "2001:67c:2960::" /etc/resolv.conf 2>/dev/null || \
       grep -q "2001:67c:2b0::" /etc/resolv.conf 2>/dev/null || \
       grep -q "2a00:1098:2c::" /etc/resolv.conf 2>/dev/null || \
       grep -q "2a01:4f8:c2c:123f::" /etc/resolv.conf 2>/dev/null; then
        echo -e " NAT64: ${green}已启用 ✓${re}"
    else
        echo -e " NAT64: ${yellow}未启用${re}"
    fi
    
    echo "-------------------------------------------------------------------"
    echo -e " 1. ${green}开启
    echo "-------------------------------------------------------------------"
    echo -e " 1. ${green}开启 Cloudflare ProxyIPv6${re}"
    echo -e " 2. ${purple}清除 Cloudflare ProxyIPv6${re}"
    echo "-------------------------------------------------------------------"
    echo -e " 3. ${cyan}配置 NAT64/DNS64 支持${re}"
    echo -e " 4. ${cyan}清除 NAT64 配置${re}"
    echo -e " 5. ${cyan}测试 NAT64 连接${re}"
    echo "-------------------------------------------------------------------"
    echo -e " 6. 查看 ip6tables 规则"
    echo -e " 7. 清空 ip6tables 规则"
    echo "-------------------------------------------------------------------"
    echo -e " 0. ${white}退出脚本${re}"
    echo "-------------------------------------------------------------------"
    read -p $'\033[1;91m请输入你的选择: \033[0m' choice

    case $choice in
        1)
            clear
            echo -e "${yellow}======================================${re}"
            echo -e "${yellow}重要提示${re}"
            echo -e "${yellow}======================================${re}"
            echo ""
            echo "你是否明白你当前的操作意味着什么？"
            echo ""
            echo -e "${purple}• 这个操作将会让你的 IP 成为反代 IP 库中的一份子${re}"
            echo -e "${purple}• 如果你的反代 IP 泄露或被扫出来，你可能失去全部流量${re}"
            echo -e "${purple}• 请不要在生产环境或重要服务器上运行${re}"
            echo -e "${purple}• 请不要在绑定了信用卡的机器上运行${re}"
            echo ""
            read -p "你确定要自行承担风险吗？(Y/N 默认N): " confirm
            confirm=${confirm^^}
            
            if [ "$confirm" == "Y" ]; then
                start 0
                echo ""
                echo -e "${green}======================================${re}"
                echo -e "${green}ProxyIP 开启成功！${re}"
                echo -e "${green}======================================${re}"
                echo -e "你的 IPv6 ProxyIP 域名: ${green}${ipv6_domain}${re}"
                echo -e "${green}======================================${re}"
            else
                echo -e "${yellow}已取消操作${re}"
            fi
            ;;

        2)
            del_ip6tables
            if [ -f /etc/iptables/rules.v6 ]; then
                rm /etc/iptables/rules.v6
            fi
            echo -e "${green}ProxyIP 规则已清除${re}"
            ;;

        3)
            setup_nat64
            ;;

        4)
            remove_nat64
            ;;

        5)
            clear
            echo -e "${cyan}======================================${re}"
            echo -e "${cyan}测试 NAT64 连接${re}"
            echo -e "${cyan}======================================${re}"
            echo ""
            
            # 检查 DNS64 配置
            dns64_server=$(grep "nameserver 2001:67c:2960::\|nameserver 2001:67c:2b0::\|nameserver 2a00:1098:2c::\|nameserver 2a01:4f8:c2c:123f::" /etc/resolv.conf | head -1 | awk '{print $2}')
            
            if [ -z "$dns64_server" ]; then
                echo -e "${red}NAT64 未配置，请先执行选项 3${re}"
            else
                echo -e "${green}检测到 DNS64: ${dns64_server}${re}"
                echo ""
                
                # 测试 1: DNS64 解析
                echo -e "${yellow}[测试 1/3] DNS64 解析测试${re}"
                echo -e "${cyan}查询 ipv4only.arpa (纯 IPv4 测试域名)${re}"
                result=$(dig AAAA ipv4only.arpa @${dns64_server} +short +time=3 2>/dev/null | head -1)
                if [ -n "$result" ]; then
                    echo -e "${green}✓ DNS64 解析成功${re}"
                    echo -e "  返回地址: ${result}"
                else
                    echo -e "${red}✗ DNS64 解析失败${re}"
                fi
                echo ""
                
                # 测试 2: 解析 IPv4-only 网站
                echo -e "${yellow}[测试 2/3] 解析 IPv4-only 网站${re}"
                echo -e "${cyan}查询 ipv4.google.com${re}"
                google_addr=$(dig AAAA ipv4.google.com +short +time=3 2>/dev/null | head -1)
                if [ -n "$google_addr" ]; then
                    echo -e "${green}✓ 解析成功${re}"
                    echo -e "  转换后地址: ${google_addr}"
                else
                    echo -e "${yellow}✗ 解析失败（可能该站点已支持 IPv6）${re}"
                fi
                echo ""
                
                # 测试 3: 实际 HTTP 连接
                echo -e "${yellow}[测试 3/3] HTTP 连接测试${re}"
                echo -e "${cyan}尝试访问 http://ipv4.google.com${re}"
                http_code=$(timeout 8 curl -6 -s --max-time 5 -o /dev/null -w "%{http_code}" "http://ipv4.google.com" 2>/dev/null)
                
                if [[ "$http_code" =~ ^(200|301|302|404)$ ]]; then
                    echo -e "${green}✓ HTTP 连接成功 (状态码: ${http_code})${re}"
                    echo -e "${green}✓ NAT64 完全可用！${re}"
                elif [ -n "$http_code" ]; then
                    echo -e "${yellow}! 收到响应但状态异常 (状态码: ${http_code})${re}"
                else
                    echo -e "${red}✗ HTTP 连接超时或失败${re}"
                    echo -e "${yellow}  提示：有些提供商可能限制了 HTTP，但 HTTPS 仍可用${re}"
                fi
                echo ""
                
                # 测试 4: HTTPS 连接（如果 HTTP 失败）
                if [[ ! "$http_code" =~ ^(200|301|302)$ ]]; then
                    echo -e "${yellow}[额外测试] HTTPS 连接测试${re}"
                    echo -e "${cyan}尝试访问 https://cloudflare.com${re}"
                    https_code=$(timeout 8 curl -6 -s --max-time 5 -o /dev/null -w "%{http_code}" "https://cloudflare.com" 2>/dev/null)
                    
                    if [[ "$https_code" =~ ^(200|301|302)$ ]]; then
                        echo -e "${green}✓ HTTPS 连接成功 (状态码: ${https_code})${re}"
                        echo -e "${green}✓ NAT64 可用（仅支持 HTTPS）${re}"
                    else
                        echo -e "${red}✗ HTTPS 也无法连接${re}"
                    fi
                fi
                
                echo ""
                echo -e "${cyan}======================================${re}"
                echo -e "${cyan}测试总结${re}"
                echo -e "${cyan}======================================${re}"
                
                if [[ "$http_code" =~ ^(200|301|302)$ ]] || [[ "$https_code" =~ ^(200|301|302)$ ]]; then
                    echo -e "${green}NAT64 工作正常，可以开启 ProxyIP${re}"
                else
                    echo -e "${yellow}NAT64 可能未完全生效${re}"
                    echo ""
                    echo "建议："
                    echo "• 等待 1-2 分钟后重试"
                    echo "• 检查防火墙设置"
                    echo "• 尝试重新配置 NAT64（选项 3）"
                fi
            fi
            
            echo ""
            read -p "按回车键继续..."
            ;;

        6)
            clear
            echo -e "${cyan}======================================${re}"
            echo -e "${cyan}当前 ip6tables 规则${re}"
            echo -e "${cyan}======================================${re}"
            echo ""
            echo -e "${yellow}NAT 表 - PREROUTING 链：${re}"
            ip6tables -t nat -L PREROUTING -v -n --line-numbers
            echo ""
            echo -e "${yellow}NAT 表 - POSTROUTING 链：${re}"
            ip6tables -t nat -L POSTROUTING -v -n --line-numbers
            echo ""
            echo -e "${cyan}======================================${re}"
            echo -e "${cyan}DNS 配置${re}"
            echo -e "${cyan}======================================${re}"
            echo ""
            cat /etc/resolv.conf
            echo ""
            read -p "按回车键继续..."
            ;;

        7)
            echo ""
            echo -e "${yellow}警告：这会清空所有 ip6tables NAT 规则！${re}"
            read -p "确定要执行吗？(Y/N 默认N): " confirm_clear
            confirm_clear=${confirm_clear^^}
            
            if [ "$confirm_clear" == "Y" ]; then
                ip6tables -t nat -F
                ip6tables -t nat -X
                
                if [ -f /etc/iptables/rules.v6 ]; then
                    rm /etc/iptables/rules.v6
                fi
                
                echo -e "${green}ip6tables 规则已清空${re}"
            else
                echo -e "${yellow}已取消操作${re}"
            fi
            ;;

        0)
            clear
            echo -e "${green}感谢使用，再见！${re}"
            exit 0
            ;;

        *)
            echo -e "${red}无效的选择！${re}"
            ;;
    esac
    
    break_end
done
