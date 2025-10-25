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

# WARP配置检测
WARP_INSTALLED=0
WARP_PROXY_PORT=40000

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

# 安装Cloudflare WARP
install_warp() {
    echo -e "${yellow}正在检查Cloudflare WARP...${re}"
    
    if command -v warp-cli &>/dev/null; then
        echo -e "${green}WARP已经安装！${re}"
        WARP_INSTALLED=1
        return 0
    fi
    
    echo -e "${yellow}开始安装Cloudflare WARP...${re}"
    
    # 添加Cloudflare仓库
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    
    # 获取系统版本代号
    source /etc/os-release
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $VERSION_CODENAME main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    
    # 安装WARP
    apt update
    apt install cloudflare-warp -y
    
    if command -v warp-cli &>/dev/null; then
        echo -e "${green}WARP安装成功！${re}"
        WARP_INSTALLED=1
        
        # 注册并配置WARP
        echo -e "${yellow}正在配置WARP...${re}"
        warp-cli registration new 2>/dev/null || warp-cli registration delete && warp-cli registration new
        warp-cli mode proxy
        warp-cli connect
        
        # 等待连接
        sleep 3
        
        if warp-cli status | grep -q "Connected"; then
            echo -e "${green}WARP连接成功！${re}"
        else
            echo -e "${red}WARP连接失败，请手动检查${re}"
            return 1
        fi
    else
        echo -e "${red}WARP安装失败！${re}"
        return 1
    fi
    
    return 0
}

# 检查域名是否支持IPv6
check_ipv6_support() {
    local domain=$1
    local ipv6s=($(dig AAAA "$domain" @2606:4700:4700::1111 +short 2>/dev/null | grep -E "$ipv6_regex"))
    
    if [ ${#ipv6s[@]} -gt 0 ]; then
        echo "ipv6"
        for ip in "${ipv6s[@]}"; do
            echo "$ip"
        done
    else
        echo "ipv4only"
    fi
}

# 获取Cloudflare IPv6地址
cf2ipv6s() {
    local domain
    cf_ipv6s=()
    for domain in "$@"; do
        ipv6s=($(dig AAAA "$domain" @2606:4700:4700::1111 +short 2>/dev/null | grep -E "$ipv6_regex"))
        cf_ipv6s+=("${ipv6s[@]}")
    done
}

# 删除现有的ip6tables规则
del_ip6tables() {
    echo -e "${yellow}清理现有的IPv6转发规则...${re}"
    
    # 检查并删除PREROUTING链中的443端口转发规则
    sudo ip6tables -t nat -L PREROUTING --line-numbers -v -n 2>/dev/null | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo ip6tables -t nat -D PREROUTING $rule_num 2>/dev/null
        echo "删除PREROUTING规则 #$rule_num"
    done

    # 检查并删除POSTROUTING链中的规则
    sudo ip6tables -t nat -L POSTROUTING --line-numbers -v -n 2>/dev/null | grep 'MASQUERADE' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo ip6tables -t nat -D POSTROUTING $rule_num 2>/dev/null
        echo "删除POSTROUTING规则 #$rule_num"
    done
}

# 停止所有WARP转发服务
stop_warp_forwards() {
    echo -e "${yellow}停止WARP转发服务...${re}"
    systemctl list-units --type=service --all | grep 'warp-forward-' | awk '{print $1}' | while read service; do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
        rm -f "/etc/systemd/system/$service" 2>/dev/null
        echo "停止并删除服务: $service"
    done
    systemctl daemon-reload
}

# 为IPv4-only站点配置WARP代理转发
setup_warp_forward() {
    local target_domain=$1
    local local_port=$2
    
    # 获取目标的IPv4地址
    local ipv4s=($(dig A "$target_domain" @1.1.1.1 +short 2>/dev/null | grep -E '^[0-9.]+$'))
    
    if [ ${#ipv4s[@]} -eq 0 ]; then
        echo -e "${red}无法获取 ${target_domain} 的IPv4地址${re}"
        return 1
    fi
    
    local target_ipv4=${ipv4s[0]}
    echo -e "${yellow}目标IPv4地址: ${target_ipv4}${re}"
    
    # 检查WARP是否运行
    if ! warp-cli status 2>/dev/null | grep -q "Connected"; then
        echo -e "${yellow}WARP未连接，正在尝试连接...${re}"
        warp-cli connect
        sleep 3
        
        if ! warp-cli status 2>/dev/null | grep -q "Connected"; then
            echo -e "${red}WARP连接失败！${re}"
            return 1
        fi
    fi
    
    # 创建systemd服务持久化运行socat
    cat > /etc/systemd/system/warp-forward-${local_port}.service <<EOF
[Unit]
Description=WARP Proxy Forward for ${target_domain} on port ${local_port}
After=network.target warp-svc.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP6-LISTEN:${local_port},fork,reuseaddr SOCKS4A:127.0.0.1:${target_ipv4}:443,socksport=${WARP_PROXY_PORT}
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable warp-forward-${local_port}.service
    systemctl restart warp-forward-${local_port}.service
    
    # 检查服务状态
    sleep 2
    if systemctl is-active --quiet warp-forward-${local_port}.service; then
        echo -e "${green}WARP转发服务启动成功！监听端口: ${local_port}${re}"
        return 0
    else
        echo -e "${red}WARP转发服务启动失败！${re}"
        systemctl status warp-forward-${local_port}.service
        return 1
    fi
}

# 获取本机IPv6地址
get_ipv6() {
    echo -e "${yellow}获取当前服务器IPv6...${re}"
    
    # 第一次尝试
    ipv6_address=$(curl -s --max-time 2 ipv6.ip.sb)
    
    # 检查IPv6地址格式
    if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
        # 第二次尝试
        ipv6_address=$(curl -s --max-time 2 ipv6.ping0.cc)
        
        if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
            if [ $NON_INTERACTIVE -eq 0 ]; then
                read -p "无法获取当前服务器的IPv6地址，是否继续（Y/N 默认N）: " gogogo
                gogogo=${gogogo^^}
                if [ "$gogogo" != "Y" ]; then
                    echo "脚本退出！"
                    exit 1
                fi
            fi
            ipv6_address="无效地址"
        fi
    fi

    # 生成域名格式
    ipv6_domain="priv.$(echo $ipv6_address | sed 's/:/-/g').ip.proy.pp.ua"

    echo -e "当前服务器IPv6: ${green}[${ipv6_address}]${re}"
}

# 保存iptables规则
save_iptables_rules() {
    echo -e "${yellow}保存iptables规则...${re}"
    
    # 确保目录存在
    mkdir -p /etc/iptables
    
    # 保存规则
    ip6tables-save > /etc/iptables/rules.v6
    
    # 配置开机自动加载
    if [ -d "/etc/network/if-pre-up.d" ]; then
        cat > /etc/network/if-pre-up.d/ip6tables <<'EOF'
#!/bin/sh
if [ -f /etc/iptables/rules.v6 ]; then
    ip6tables-restore < /etc/iptables/rules.v6
fi
exit 0
EOF
        chmod +x /etc/network/if-pre-up.d/ip6tables
        echo -e "${green}已配置网络启动时自动加载规则${re}"
    elif [ -d "/etc/systemd/system" ]; then
        cat > /etc/systemd/system/ip6tables-restore.service <<'EOF'
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
        systemctl enable ip6tables-restore.service
        echo -e "${green}已配置systemd服务自动加载规则${re}"
    fi
}

# 主启动函数
start() {
    local non_interactive=${1:-0}
    
    get_ipv6

    # 安装基础依赖
    if [ $non_interactive -eq 1 ]; then
        echo -e "${yellow}自动安装依赖包...${re}"
        install sudo ss iptables dig curl socat
    else
        echo -e "脚本所需依赖包: ${yellow}curl, sudo, ss, iptables, dig, socat${re}"
        read -p "是否允许脚本自动安装以上所需的依赖包(Y/N 默认Y): " install_apps
        install_apps=${install_apps^^}
        install_apps=${install_apps:-Y}
        if [ "$install_apps" == "Y" ]; then
            install sudo ss iptables dig curl socat
        fi
    fi

    # 检查并安装WARP
    echo ""
    echo -e "${purple}════════════════════════════════════════${re}"
    echo -e "${purple}  检测到你需要访问IPv4-only的网站  ${re}"
    echo -e "${purple}  需要安装Cloudflare WARP作为代理  ${re}"
    echo -e "${purple}════════════════════════════════════════${re}"
    echo ""
    
    if [ $non_interactive -eq 0 ]; then
        read -p "是否安装/检查Cloudflare WARP (Y/N 默认Y): " install_warp_confirm
        install_warp_confirm=${install_warp_confirm^^}
        install_warp_confirm=${install_warp_confirm:-Y}
        if [ "$install_warp_confirm" != "Y" ]; then
            echo -e "${yellow}跳过WARP安装，将只使用IPv6直连模式${re}"
            WARP_INSTALLED=0
        else
            install_warp
        fi
    else
        install_warp
    fi

    # 开启IPv6转发
    echo ""
    echo -e "${yellow}配置IPv6流量转发...${re}"
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
        echo -e "${green}IPv6流量转发已添加${re}"
    fi
    sysctl -p >/dev/null 2>&1
    echo -e "${green}IPv6流量转发已开启${re}"

    # 获取端口
    if [ $non_interactive -eq 1 ]; then
        local_port=$PORT_PARAM
    else
        read -p $'请输入ProxyIP的本地端口（默认 443）: ' local_port
        local_port=${local_port:-443}
    fi
    
    # 验证端口
    if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [ "$local_port" -lt 1 ] || [ "$local_port" -gt 65535 ]; then
        echo -e "${red}错误: 无效的端口号！${re}"
        return 1
    fi
    
    if ss -tuln | grep -q ":${local_port} "; then
        echo -e "${red}${local_port}端口已被占用！${re}"
        return 1
    fi

    # 检测Cloudflare节点是否支持IPv6
    echo ""
    echo -e "${yellow}正在检测Cloudflare节点连接性...${re}"
    cf_result=$(check_ipv6_support "cloudflare.com")
    
    # 清理旧规则
    del_ip6tables
    stop_warp_forwards
    
    if [[ $cf_result == ipv6* ]]; then
        # 支持IPv6 - 使用直连模式
        echo -e "${green}✓ 检测到IPv6支持，使用直连模式${re}"
        
        # 获取IPv6地址列表
        mapfile -t cf_ipv6s < <(echo "$cf_result" | tail -n +2)
        
        if [ ${#cf_ipv6s[@]} -eq 0 ]; then
            echo -e "${red}无法获取Cloudflare IPv6地址${re}"
            return 1
        fi
        
        # 随机选择一个IPv6
        random_ipv6=$(printf "%s\n" "${cf_ipv6s[@]}" | shuf -n 1)
        echo -e "使用CF节点: ${yellow}${random_ipv6}${re}"
        
        # 配置ip6tables规则
        ip6tables -t nat -A PREROUTING -p tcp --dport $local_port -j DNAT --to-destination [$random_ipv6]:443
        ip6tables -t nat -A POSTROUTING -j MASQUERADE
        
        echo -e "${green}✓ IPv6直连模式配置完成${re}"
        
    else
        # 仅支持IPv4 - 使用WARP代理模式
        echo -e "${yellow}✓ 检测到目标仅支持IPv4，使用WARP代理模式${re}"
        
        if [ $WARP_INSTALLED -eq 0 ]; then
            echo -e "${red}WARP未安装，无法访问IPv4-only网站！${re}"
            return 1
        fi
        
        # 配置WARP转发
        if setup_warp_forward "cloudflare.com" "$local_port"; then
            echo -e "${green}✓ WARP代理模式配置完成${re}"
        else
            echo -e "${red}WARP代理配置失败！${re}"
            return 1
        fi
    fi
    
    # 保存规则
    save_iptables_rules
    
    echo ""
    echo -e "${green}════════════════════════════════════════${re}"
    echo -e "${green}  ProxyIP 配置成功！  ${re}"
    echo -e "${green}════════════════════════════════════════${re}"
    echo -e "监听端口: ${yellow}${local_port}${re}"
    echo -e "ProxyIP域名: ${green}${ipv6_domain}${re}"
    if [[ $cf_result == ipv6* ]]; then
        echo -e "工作模式: ${green}IPv6直连${re}"
    else
        echo -e "工作模式: ${yellow}WARP代理（支持IPv4-only网站）${re}"
    fi
    echo -e "${green}════════════════════════════════════════${re}"
}

# 查看状态
show_status() {
    clear
    echo -e "${skyblue}════════════════════════════════════════${re}"
    echo -e "${skyblue}  ProxyIP 运行状态  ${re}"
    echo -e "${skyblue}════════════════════════════════════════${re}"
    echo ""
    
    # 检查ip6tables规则
    echo -e "${yellow}【IPv6转发规则】${re}"
    if ip6tables -t nat -L PREROUTING -n -v 2>/dev/null | grep -q 'tcp dpt:443'; then
        ip6tables -t nat -L PREROUTING -n -v | grep 'tcp dpt:443'
        echo -e "${green}✓ IPv6转发规则已配置${re}"
    else
        echo -e "${red}✗ 未找到IPv6转发规则${re}"
    fi
    
    echo ""
    echo -e "${yellow}【WARP状态】${re}"
    if command -v warp-cli &>/dev/null; then
        warp_status=$(warp-cli status 2>/dev/null)
        echo "$warp_status"
        if echo "$warp_status" | grep -q "Connected"; then
            echo -e "${green}✓ WARP已连接${re}"
        else
            echo -e "${red}✗ WARP未连接${re}"
        fi
    else
        echo -e "${red}✗ WARP未安装${re}"
    fi
    
    echo ""
    echo -e "${yellow}【WARP转发服务】${re}"
    warp_services=$(systemctl list-units --type=service --all | grep 'warp-forward-' | awk '{print $1, $3, $4}')
    if [ -n "$warp_services" ]; then
        echo "$warp_services"
    else
        echo -e "${yellow}未配置WARP转发服务（当前可能使用IPv6直连模式）${re}"
    fi
    
    echo ""
    get_ipv6
    echo -e "ProxyIP域名: ${green}${ipv6_domain}${re}"
}

#########################主菜单##############################

# 无交互模式
if [ $NON_INTERACTIVE -eq 1 ]; then
    echo -e "${purple}无交互模式启动...${re}"
    echo "你是否明白你当前的操作意味着什么？"
    echo -e "${purple}这个操作将会让你的IP成为反代IP库中的一份子${re}"
    echo -e "${purple}如果你的反代IP泄露或被扫描，你可能会失去流量！${re}"
    start 1
    exit 0
fi

# 交互模式主循环
while true; do
    get_ipv6
    clear
    echo -e "${yellow} ____                      ___ ____         __   ${re}"
    echo -e "${yellow}|  _ \\ _ __ _____  ___   _|_ _|  _ \\__   __/ /_  ${re}"
    echo -e "${yellow}| |_) | '__/ _ \\ \\/ / | | || || |_) \\ \\ / / '_ \\ ${re}"
    echo -e "${yellow}|  __/| | | (_) >  <| |_| || ||  __/ \\ V /| (_) |${re}"
    echo -e "${yellow}|_|   |_|  \\___/_/\\_\\\\__,  |___|_|     \\_/  \\___/ ${re}"
    echo -e "               改进版   ${yellow}|___/${re}              "    
    echo "-------------------------------------------------------------------"
    echo " 配置信息:" 
    echo -e " IPv6: ${green}[${ipv6_address}]${re}"
    echo -e " ProxyIP: ${green}${ipv6_domain}${re}"
    echo "-------------------------------------------------------------------"
    echo -e " ${green}1.${re} 开启 Cloudflare ProxyIPv6 ${yellow}(智能分流IPv4/IPv6)${re}"
    echo -e " ${purple}2.${re} 清除 Cloudflare ProxyIPv6"
    echo -e " ${skyblue}3.${re} 查看 ProxyIP 运行状态"
    echo "-------------------------------------------------------------------"
    echo -e " ${yellow}4.${re} 安装/重连 Cloudflare WARP"
    echo -e " ${yellow}5.${re} 查看 ip6tables 所有规则"
    echo -e " ${red}6.${re} 清空 ip6tables 所有规则 ${red}(危险操作)${re}"
    echo "-------------------------------------------------------------------"
    echo -e " ${white}0.${re} 退出脚本" 
    echo "-------------------------------------------------------------------"
    read -p $'\033[1;91m请输入你的选择: \033[0m' choice

    case $choice in
        1)
            clear
            echo -e "${purple}════════════════════════════════════════${re}"
            echo -e "${purple}  重要提示！请仔细阅读  ${re}"
            echo -e "${purple}════════════════════════════════════════${re}"
            echo "你是否明白你当前的操作意味着什么？"
            echo ""
            echo -e "${purple}• 这个操作将会让你的VPS成为反代节点${re}"
            echo -e "${purple}• 如果你的ProxyIP泄露或被扫描，可能会消耗大量流量${re}"
            echo -e "${purple}• 请不要在生产环境或重要服务器上运行此脚本${re}"
            echo -e "${purple}• 请不要在绑定信用卡的机器上运行此脚本${re}"
            echo ""
            read -p "你确定要自行承担这个风险吗？（Y/N 默认N）: " fxxkme
            fxxkme=${fxxkme^^}
            if [ "$fxxkme" == "Y" ]; then
                start 0
            else
                echo -e "${yellow}已取消操作${re}"
            fi
            ;;

        2)
            echo -e "${yellow}正在清除ProxyIP配置...${re}"
            del_ip6tables
            stop_warp_forwards
            echo -e "${green}清除完成！${re}"
            ;;

        3)
            show_status
            ;;

        4)
            clear
            echo -e "${yellow}正在安装/检查WARP...${re}"
            install_warp
            if [ $? -eq 0 ]; then
                echo -e "${green}WARP配置完成！${re}"
                warp-cli status
            fi
            ;;

        5)
            clear
            echo -e "${yellow}【NAT表规则】${re}"
            ip6tables -t nat -L -v -n
            echo ""
            echo -e "${yellow}【Filter表规则】${re}"
            ip6tables -t filter -L -v -n
            ;;

        6)
            echo -e "${red}════════════════════════════════════════${re}"
            echo -e "${red}  危险操作警告！  ${re}"
            echo -e "${red}════════════════════════════════════════${re}"
            echo "这个操作将会清空所有ip6tables规则！"
            echo "不仅是ProxyIP的规则，而是所有IPv6防火墙规则！"
            echo ""
            read -p "你确定要执行吗？（输入YES确认）: " fxxkip6tables
            if [ "$fxxkip6tables" == "YES" ]; then
                ip6tables -t nat -F
                ip6tables -t filter -F
                echo -e "${green}所有ip6tables规则已清空！${re}"
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
            echo -e "${red}无效的输入！${re}"
            ;;
    esac
    break_end
done
