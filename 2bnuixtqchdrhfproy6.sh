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
            apt update -qq
            apt install -y "$package"
        elif command -v dnf &>/dev/null; then
            dnf install -y "$package"
        elif command -v yum &>/dev/null; then
            yum install -y "$package"
        elif command -v apk &>/dev/null; then
            apk add "$package"
        else
            echo -e"${red}暂不支持你的系统!${re}"
            return 1
        fi
    done

    return 0
}

cf2ipv6s() {
    local domain
    cf_ipv6s=()
    for domain in "$@"; do
        ipv6s=($(dig AAAA "$domain" @2606:4700:4700::1111 +short | grep -E "$ipv6_regex"))
        cf_ipv6s+=("${ipv6s[@]}")
    done
}

del_ip6tables() {
    # 检查并删除PREROUTING链中的443端口转发规则
    sudo ip6tables -t nat -L PREROUTING --line-numbers -v -n | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo ip6tables -t nat -D PREROUTING $rule_num
        echo "检查并删除现有的PREROUTING链中的443端口转发规则"
    done

    # 检查并删除POSTROUTING链中的443端口转发规则
    sudo ip6tables -t nat -L POSTROUTING --line-numbers -v -n | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo ip6tables -t nat -D POSTROUTING $rule_num
        echo "检查并删除现有的POSTROUTING链中的443端口转发规则"
    done
}

get_ipv6() {
    echo "获取当前服务器IPv6"
    # 第一次尝试获取IPv6地址
    ipv6_address=$(curl -s --max-time 1 ipv6.ip.sb)
    # 检查IPv6地址格式
    if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
        # 如果格式不正确，使用第二个API获取IPv6地址
        ipv6_address=$(curl -s --max-time 1 ipv6.ping0.cc)
        # 再次检查IPv6地址格式
        if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
            read -p "无法获取当前服务器的IPv6地址，是否继续（Y/N 默认N）:" gogogo
            gogogo=${gogogo^^} # 转换为大写
            if [ "$gogogo" == "Y" ]; then
                echo "因无法获取当前服务器的IPv6地址，之后脚本显示的IPv6和域名格式均无法直接使用！"
                ipv6_address="无效地址"
            else
                echo "脚本退出！"
                exit 1
            fi
        fi
    fi

    # 替换冒号为短横线
    ipv6_domain="priv.$(echo $ipv6_address | sed 's/:/-/g').ip.proy.pp.ua"

    echo -e "当前服务器IPv6:${green} [${ipv6_address}]${re}"
}

# 定义允许访问的IPv6地址段数组
ipv6_addresses=(
    2400:cb00::/32
    2606:4700::/32
    2803:f800::/32
    2405:b500::/32
    2405:8100::/32
    2a06:98c0::/29
    2c0f:f248::/32
)

# ==================== WARP 相关功能 ====================

check_warp_status() {
    if ! command -v warp-cli &> /dev/null; then
        echo -e "${red}WARP 未安装${re}"
        return 1
    fi
    
    local status=$(warp-cli status 2>/dev/null | grep "Status update:" | awk '{print $3}')
    if [ "$status" == "Connected" ]; then
        echo -e "${green}WARP 已连接（代理模式: socks5://127.0.0.1:40000）${re}"
        return 0
    else
        echo -e "${yellow}WARP 已安装但未连接${re}"
        return 2
    fi
}

install_warp() {
    echo -e "${yellow}=== 安装 Cloudflare WARP ===${re}"
    echo "WARP 将以代理模式运行，不会影响你的 iptables 规则"
    echo "可通过 socks5://127.0.0.1:40000 访问 IPv4 网络"
    echo ""
    
    # 检测系统类型
    if ! command -v lsb_release &> /dev/null; then
        install lsb-release
    fi
    
    local os_codename=$(lsb_release -cs)
    
    echo "1. 添加 Cloudflare WARP 仓库..."
    if [ ! -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg ]; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | \
        sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    fi
    
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ ${os_codename} main" | \
    sudo tee /etc/apt/sources.list.d/cloudflare-client.list > /dev/null
    
    echo "2. 更新软件包列表..."
    sudo apt update -qq
    
    echo "3. 安装 cloudflare-warp..."
    sudo apt install -y cloudflare-warp
    
    echo "4. 注册 WARP..."
    warp-cli register
    
    echo "5. 设置为代理模式（关键：不影响系统路由）..."
    warp-cli set-mode proxy
    
    echo "6. 连接 WARP..."
    warp-cli connect
    
    sleep 3
    
    echo ""
    echo -e "${green}=== WARP 安装完成！===${re}"
    echo ""
    echo "测试 WARP 连接："
    if curl -x socks5://127.0.0.1:40000 -s --max-time 5 http://ip-api.com/json 2>/dev/null | grep -q "country"; then
        echo -e "${green}✓ WARP 代理工作正常${re}"
        echo ""
        echo "你现在可以通过以下方式使用 IPv4 网络："
        echo "  方式1: curl -x socks5://127.0.0.1:40000 http://ipv4.google.com"
        echo "  方式2: export ALL_PROXY=socks5://127.0.0.1:40000"
        echo "  方式3: 使用脚本提供的便捷命令（菜单选项 6）"
    else
        echo -e "${red}✗ WARP 代理似乎未正常工作${re}"
        echo "请检查日志: warp-cli status"
    fi
}

uninstall_warp() {
    echo -e "${yellow}=== 卸载 Cloudflare WARP ===${re}"
    
    if command -v warp-cli &> /dev/null; then
        echo "1. 断开连接..."
        warp-cli disconnect 2>/dev/null
        
        echo "2. 卸载软件包..."
        sudo apt remove -y cloudflare-warp
        sudo apt autoremove -y
        
        echo "3. 清理配置文件..."
        sudo rm -f /etc/apt/sources.list.d/cloudflare-client.list
        sudo rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        sudo rm -rf /var/lib/cloudflare-warp
        
        echo -e "${green}WARP 已完全卸载${re}"
    else
        echo -e "${yellow}WARP 未安装${re}"
    fi
}

toggle_warp() {
    if ! command -v warp-cli &> /dev/null; then
        echo -e "${red}WARP 未安装，请先安装（菜单选项 5）${re}"
        return 1
    fi
    
    local status=$(warp-cli status 2>/dev/null | grep "Status update:" | awk '{print $3}')
    
    if [ "$status" == "Connected" ]; then
        echo "断开 WARP 连接..."
        warp-cli disconnect
        echo -e "${yellow}WARP 已断开${re}"
    else
        echo "连接 WARP..."
        warp-cli connect
        sleep 2
        echo -e "${green}WARP 已连接${re}"
        echo "代理地址: socks5://127.0.0.1:40000"
    fi
}

create_warp_shortcuts() {
    echo -e "${yellow}=== 创建 WARP 便捷命令 ===${re}"
    
    # 创建便捷脚本
    cat > /usr/local/bin/warp-curl << 'WARPEOF'
#!/bin/bash
curl -x socks5://127.0.0.1:40000 "$@"
WARPEOF
    
    cat > /usr/local/bin/warp-wget << 'WARPEOF'
#!/bin/bash
ALL_PROXY=socks5://127.0.0.1:40000 wget "$@"
WARPEOF
    
    cat > /usr/local/bin/warp-toggle << 'WARPEOF'
#!/bin/bash
if warp-cli status 2>/dev/null | grep -q "Connected"; then
    warp-cli disconnect
    echo "WARP 已断开"
else
    warp-cli connect
    echo "WARP 已连接（socks5://127.0.0.1:40000）"
fi
WARPEOF
    
    sudo chmod +x /usr/local/bin/warp-curl
    sudo chmod +x /usr/local/bin/warp-wget
    sudo chmod +x /usr/local/bin/warp-toggle
    
    echo -e "${green}便捷命令创建成功！${re}"
    echo ""
    echo "可用命令："
    echo "  ${green}warp-curl${re} http://ipv4.google.com  # 通过 WARP 使用 curl"
    echo "  ${green}warp-wget${re} http://example.com/file  # 通过 WARP 使用 wget"
    echo "  ${green}warp-toggle${re}                        # 快速切换 WARP 开关"
    echo ""
    echo "或者直接设置环境变量："
    echo "  export ALL_PROXY=socks5://127.0.0.1:40000"
    echo "  curl http://ipv4-only-site.com"
    echo "  unset ALL_PROXY"
}

test_warp() {
    echo -e "${yellow}=== 测试 WARP 功能 ===${re}"
    echo ""
    
    if ! command -v warp-cli &> /dev/null; then
        echo -e "${red}WARP 未安装${re}"
        return 1
    fi
    
    local status=$(warp-cli status 2>/dev/null | grep "Status update:" | awk '{print $3}')
    if [ "$status" != "Connected" ]; then
        echo -e "${yellow}WARP 未连接，尝试连接...${re}"
        warp-cli connect
        sleep 3
    fi
    
    echo "1. 测试 WARP 代理连接..."
    if nc -zv 127.0.0.1 40000 2>&1 | grep -q "succeeded\|open"; then
        echo -e "${green}✓ SOCKS5 端口 40000 可访问${re}"
    else
        echo -e "${red}✗ SOCKS5 端口 40000 不可访问${re}"
        return 1
    fi
    
    echo ""
    echo "2. 测试 IPv4 访问..."
    local ipv4_result=$(curl -x socks5://127.0.0.1:40000 -s --max-time 5 http://ip-api.com/json 2>/dev/null)
    if echo "$ipv4_result" | grep -q "country"; then
        local country=$(echo "$ipv4_result" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        local ip=$(echo "$ipv4_result" | grep -o '"query":"[^"]*"' | cut -d'"' -f4)
        echo -e "${green}✓ IPv4 网络可访问${re}"
        echo "  出口 IP: ${ip}"
        echo "  国家: ${country}"
    else
        echo -e "${red}✗ IPv4 网络访问失败${re}"
        return 1
    fi
    
    echo ""
    echo "3. 测试常见网站访问..."
    
    test_sites=(
        "http://ipv4.google.com|Google"
        "http://api.ipify.org|ipify"
        "http://checkip.amazonaws.com|AWS"
    )
    
    for site in "${test_sites[@]}"; do
        IFS='|' read -r url name <<< "$site"
        if timeout 5 curl -x socks5://127.0.0.1:40000 -s "$url" > /dev/null 2>&1; then
            echo -e "  ${green}✓${re} ${name}: 可访问"
        else
            echo -e "  ${red}✗${re} ${name}: 不可访问"
        fi
    done
    
    echo ""
    echo -e "${green}=== 测试完成 ===${re}"
}

# ==================== 主程序 ====================

start() {
    local non_interactive=${1:-0}
    
    get_ipv6

    if [ $non_interactive -eq 1 ]; then
        echo -e "自动安装依赖包..."
        install sudo ss iptables dig printf shuf
    else
        echo -e "脚本所需依赖包 ${yellow}curl,sudo,ss,iptables,dig,printf,shuf ${re}"
        read -p "是否允许脚本自动安装以上所需的依赖包(Y): " install_apps
        install_apps=${install_apps^^} # 转换为大写
        if [ "$install_apps" == "Y" ]; then
            install sudo ss iptables dig printf shuf
        fi
    fi

    echo "检查IPv6的流量转发功能"
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
        echo "IPv6的流量转发 成功添加"
    fi

    # 应用配置
    sudo sysctl -p
    echo "IPv6的流量转发 已开启"

    cf2ipv6s ip.sb time.is

    # 检查数组是否为空
    if [ ${#cf_ipv6s[@]} -eq 0 ]; then
        echo "未找到符合要求的IPv6地址"
        exit 1
    fi

    # 随机选择一个IPv6地址
    random_ipv6=$(printf "%s\n" "${cf_ipv6s[@]}" | shuf -n 1)

    # 输出随机选择的IPv6地址
    echo -e "成功获取 Cloudflare CDN 的IPv6地址: ${yellow}${random_ipv6}${re}"

    del_ip6tables

    if [ $non_interactive -eq 1 ]; then
        local_port=$PORT_PARAM
    else
        read -p $'请输入你的ProxyIP的本地端口（默认 443）' local_port
        local_port=${local_port:-443}
    fi
    
    if ss -tuln | grep -q ":${local_port} "; then
        echo -e "${local_port}端口已被占用，退出脚本。请自行检查${local_port}端口占用问题"
        exit 1
    fi

    # 验证端口号是否有效
    if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [ "$local_port" -lt 1 ] || [ "$local_port" -gt 65535 ]; then
        echo -e "${red}错误: 无效的端口号! 端口必须是1-65535之间的数字。${re}"
        return 1
    fi
    
    echo -e "添加 ${yellow}${random_ipv6}${re} 的PREROUTING链中的${local_port}端口转发规则"
    sudo ip6tables -t nat -A PREROUTING -p tcp --dport $local_port -j DNAT --to-destination [$random_ipv6]:443

    # 通用规则（针对所有流量）:
    sudo ip6tables -t nat -A POSTROUTING -j MASQUERADE

    echo "添加重启守护 ip6tables 规则"
    # 确保目录存在
    if [ ! -d "/etc/iptables" ]; then
        echo "创建 /etc/iptables 目录"
        sudo mkdir -p /etc/iptables
    fi
    
    # 保存规则并检查是否成功
    if sudo ip6tables-save > /tmp/rules.v6_temp && sudo mv /tmp/rules.v6_temp /etc/iptables/rules.v6; then
        echo "规则已成功保存到 /etc/iptables/rules.v6"
    else
        echo -e "${red}规则保存失败!${re}"
    fi
    
    # 检查是否能够成功恢复规则
    if [ -f "/etc/iptables/rules.v6" ]; then
        if sudo ip6tables-restore < /etc/iptables/rules.v6; then
            echo "规则已成功应用"
        else
            echo -e "${red}规则应用失败!${re}"
        fi
    else
        echo -e "${red}规则文件不存在，无法应用!${re}"
    fi
    
    # 确保系统重启后规则依然生效
    if [ -d "/etc/network/if-pre-up.d" ]; then
        echo "配置网络启动时自动加载规则"
        echo "#!/bin/sh
if [ -f /etc/iptables/rules.v6 ]; then
    ip6tables-restore < /etc/iptables/rules.v6
fi
exit 0" | sudo tee /etc/network/if-pre-up.d/ip6tables > /dev/null
        sudo chmod +x /etc/network/if-pre-up.d/ip6tables
    elif [ -d "/etc/systemd/system" ]; then
        echo "配置systemd服务自动加载规则"
        echo "[Unit]
Description=Restore ip6tables rules
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/ip6tables-restore /etc/iptables/rules.v6
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/ip6tables-restore.service > /dev/null
        sudo systemctl daemon-reload
        sudo systemctl enable ip6tables-restore.service
    fi
}

#########################梦开始的地方##############################

# 如果处于无交互模式，直接执行开启操作
if [ $NON_INTERACTIVE -eq 1 ]; then
    echo "检测到无交互参数 ${PORT_PARAM}，自动开启Cloudflare ProxyIPv6..."
    echo "你是否明白你当前的操作意味着什么？"
    echo -e "${purple}这个操作将会让你的IP成为反代IP库中的一份子，如果你的反代IP泄露或被人扫出来，你将会失去你全部流量！！！${re}"
    echo -e "${purple}请不要在生产力机器上执行这个脚本！更不要在绑定了你的信用卡的机器上运行这个脚本！${re}"
    start 1
    echo -e "开启ProxyIP成功，端口:${yellow}${PORT_PARAM}${re}，你的IPv6_ProxyIP域名: ${green}${ipv6_domain}${re}"
    exit 0
fi

while true; do
get_ipv6

# 获取 WARP 状态
warp_status_text="未安装"
warp_status_color="${red}"
if command -v warp-cli &> /dev/null; then
    local status=$(warp-cli status 2>/dev/null | grep "Status update:" | awk '{print $3}')
    if [ "$status" == "Connected" ]; then
        warp_status_text="已连接 (socks5://127.0.0.1:40000)"
        warp_status_color="${green}"
    else
        warp_status_text="已安装未连接"
        warp_status_color="${yellow}"
    fi
fi

clear
echo -e "${yellow} ____                      ___ ____         __   ${re}"
echo -e "${yellow}|  _ \\ _ __ _____  ___   _|_ _|  _ \\__   __/ /_  ${re}"
echo -e "${yellow}| |_) | '__/ _ \\ \\/ / | | || || |_) \\ \\ / / '_ \\ ${re}"
echo -e "${yellow}|  __/| | | (_) >  <| |_| || ||  __/ \\ V /| (_) |${re}"
echo -e "${yellow}|_|   |_|  \\___/_/\\_\\\\__,  |___|_|     \\_/  \\___/ ${re}"
echo -e " 作者: cmliu         ${yellow}|___/${re} TG交流群: t.me/CMLiussss"    
echo "-------------------------------------------------------------------"
echo " 配置信息:" 
echo -e " IPv6:${green} [${ipv6_address}]${re}"
echo -e " ProxyIP:${green} ${ipv6_domain}${re}"
echo -e " WARP 状态:${warp_status_color} ${warp_status_text}${re}"
echo "-------------------------------------------------------------------"
echo -e " 1. ${green}开启 Cloudflare ProxyIPv6 ${re}"
echo -e " 2. ${purple}清除 Cloudflare ProxyIPv6 ${re}"
echo "-------------------------------------------------------------------"
echo -e " 3. 查看 ip6tables 所有规则信息"
echo -e " 4. 清空 ip6tables 所有规则信息"
echo "-------------------------------------------------------------------"
echo -e " ${skyblue}WARP 功能（IPv4 访问支持）:${re}"
echo -e " 5. 安装/配置 Cloudflare WARP"
echo -e " 6. 创建 WARP 便捷命令"
echo -e " 7. 测试 WARP 功能"
echo -e " 8. 切换 WARP 开关"
echo -e " 9. 卸载 WARP"
echo "-------------------------------------------------------------------"
echo -e "\033[0;97m 0. 退出脚本" 
echo "-------------------------------------------------------------------"
read -p $'\033[1;91m请输入你的选择: \033[0m' choice

case $choice in
  1)
    clear
    echo "你是否明白你当前的操作意味着什么？"
    echo -e "${purple}这个操作将会让你的IP成为反代IP库中的一份子，如果你的反代IP泄露或被人扫出来，你将会失去你全部流量！！！${re}"
    echo -e "${purple}请不要在生产力机器上执行这个脚本！更不要在绑定了你的信用卡的机器上运行这个脚本！${re}"
    read -p "你确定你要自行承担这个风险了吗？（Y/N 默认N）" fxxkme
    fxxkme=${fxxkme^^} # 转换为大写
    if [ "$fxxkme" == "Y" ]; then
        start 0
        echo -e "开启ProxyIP成功，你的IPv6_ProxyIP域名: ${green}${ipv6_domain}${re}"
    fi
    ;;

  2)
    del_ip6tables
    ;;

  3)
    sudo ip6tables -t nat -L -v -n
    ;;  
    
  4)
    read -p "这操作不单只是清空该脚本的规则，而是将 ip6tables 规则完全清空，你确定要执行吗（Y/N 默认N）" fxxkip6tables
    fxxkip6tables=${fxxkip6tables^^} # 转换为大写
    if [ "$fxxkip6tables" == "Y" ]; then
        sudo ip6tables -t nat -F
    fi
    ;;

  5)
    clear
    if command -v warp-cli &> /dev/null; then
        echo -e "${yellow}WARP 已安装${re}"
        check_warp_status
        echo ""
        read -p "是否重新安装 WARP？（Y/N 默认N）" reinstall_warp
        reinstall_warp=${reinstall_warp^^}
        if [ "$reinstall_warp" == "Y" ]; then
            uninstall_warp
            echo ""
            install_warp
        fi
    else
        install_warp
    fi
    ;;

  6)
    clear
    if ! command -v warp-cli &> /dev/null; then
        echo -e "${red}WARP 未安装，请先安装（选项 5）${re}"
    else
        create_warp_shortcuts
    fi
    ;;

  7)
    clear
    test_warp
    ;;

  8)
    clear
    toggle_warp
    ;;

  9)
    clear
    read -p "确定要卸载 WARP 吗？（Y/N 默认N）" uninstall_confirm
    uninstall_confirm=${uninstall_confirm^^}
    if [ "$uninstall_confirm" == "Y" ]; then
        uninstall_warp
    fi
    ;;

  0)
    clear
    exit
    ;;

  *)
    echo -e "${red}无效的输入!${re}"
    ;;
esac
    break_end
done


  
