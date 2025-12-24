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
IP_VERSION="auto"  # auto, ipv4, ipv6
if [ -n "$1" ]; then
    NON_INTERACTIVE=1
    PORT_PARAM="$1"
    if [ -n "$2" ]; then
        IP_VERSION="$2"
    fi
fi

# 定义IPv6地址的正则表达式
ipv6_regex="^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]|[1-9]?)?[0-9]))$"

# 定义IPv4地址的正则表达式
ipv4_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

# 全局变量
USE_IPV4=0
USE_IPV6=0
ipv4_domain=""
ipv6_domain=""

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

# 获取 Cloudflare CDN 的 IPv4 地址
cf2ipv4s() {
    local domain
    cf_ipv4s=()
    for domain in "$@"; do
        ipv4s=($(dig A "$domain" @1.1.1.1 +short | grep -E "$ipv4_regex"))
        cf_ipv4s+=("${ipv4s[@]}")
    done
}

# 获取 Cloudflare CDN 的 IPv6 地址
cf2ipv6s() {
    local domain
    cf_ipv6s=()
    for domain in "$@"; do
        ipv6s=($(dig AAAA "$domain" @2606:4700:4700::1111 +short | grep -E "$ipv6_regex"))
        cf_ipv6s+=("${ipv6s[@]}")
    done
}

# 删除 IPv4 iptables 规则
del_iptables() {
    # 检查并删除PREROUTING链中的443端口转发规则
    sudo iptables -t nat -L PREROUTING --line-numbers -v -n | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo iptables -t nat -D PREROUTING $rule_num
        echo "检查并删除现有的IPv4 PREROUTING链中的443端口转发规则"
    done

    # 检查并删除POSTROUTING链中的443端口转发规则
    sudo iptables -t nat -L POSTROUTING --line-numbers -v -n | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo iptables -t nat -D POSTROUTING $rule_num
        echo "检查并删除现有的IPv4 POSTROUTING链中的443端口转发规则"
    done
}

# 删除 IPv6 ip6tables 规则
del_ip6tables() {
    # 检查并删除PREROUTING链中的443端口转发规则
    sudo ip6tables -t nat -L PREROUTING --line-numbers -v -n | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo ip6tables -t nat -D PREROUTING $rule_num
        echo "检查并删除现有的IPv6 PREROUTING链中的443端口转发规则"
    done

    # 检查并删除POSTROUTING链中的443端口转发规则
    sudo ip6tables -t nat -L POSTROUTING --line-numbers -v -n | grep 'tcp dpt:443' | while read -r line ; do
        rule_num=$(echo $line | awk '{print $1}')
        sudo ip6tables -t nat -D POSTROUTING $rule_num
        echo "检查并删除现有的IPv6 POSTROUTING链中的443端口转发规则"
    done
}

# 获取当前服务器的 IPv4 地址
get_ipv4() {
    echo "获取当前服务器IPv4"
    # 第一次尝试获取IPv4地址
    ipv4_address=$(curl -s --max-time 1 -4 ip.sb)
    # 检查IPv4地址格式
    if [[ ! $ipv4_address =~ $ipv4_regex ]]; then
        # 如果格式不正确，使用第二个API获取IPv4地址
        ipv4_address=$(curl -s --max-time 1 -4 ifconfig.me)
        # 再次检查IPv4地址格式
        if [[ ! $ipv4_address =~ $ipv4_regex ]]; then
            echo -e "${red}无法获取当前服务器的IPv4地址${re}"
            ipv4_address=""
            ipv4_domain=""
            return 1
        fi
    fi

    # 生成 IPv4 对应的域名格式（使用 myis.me 服务，将点替换为短横线）
    ipv4_domain="priv.$(echo $ipv4_address | sed 's/\./-/g').myis.me"

    echo -e "当前服务器IPv4:${green} ${ipv4_address}${re}"
    echo -e "IPv4 ProxyIP域名:${green} ${ipv4_domain}${re}"
    return 0
}

# 获取当前服务器的 IPv6 地址
get_ipv6() {
    echo "获取当前服务器IPv6"
    # 第一次尝试获取IPv6地址
    ipv6_address=$(curl -s --max-time 1 -6 ipv6.ip.sb)
    # 检查IPv6地址格式
    if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
        # 如果格式不正确，使用第二个API获取IPv6地址
        ipv6_address=$(curl -s --max-time 1 -6 ipv6.ping0.cc)
        # 再次检查IPv6地址格式
        if [[ ! $ipv6_address =~ $ipv6_regex ]]; then
            echo -e "${red}无法获取当前服务器的IPv6地址${re}"
            ipv6_address=""
            ipv6_domain=""
            return 1
        fi
    fi

    # 替换冒号为短横线，生成 IPv6 域名
    ipv6_domain="priv.$(echo $ipv6_address | sed 's/:/-/g').myis.me"

    echo -e "当前服务器IPv6:${green} [${ipv6_address}]${re}"
    echo -e "IPv6 ProxyIP域名:${green} ${ipv6_domain}${re}"
    return 0
}

# 定义允许访问的 Cloudflare IPv4 地址段数组
ipv4_addresses=(
    173.245.48.0/20
    103.21.244.0/22
    103.22.200.0/22
    103.31.4.0/22
    141.101.64.0/18
    108.162.192.0/18
    190.93.240.0/20
    188.114.96.0/20
    197.234.240.0/22
    198.41.128.0/17
    162.158.0.0/15
    104.16.0.0/13
    104.24.0.0/14
    172.64.0.0/13
    131.0.72.0/22
)

# 定义允许访问的 Cloudflare IPv6 地址段数组
ipv6_addresses=(
    2400:cb00::/32
    2606:4700::/32
    2803:f800::/32
    2405:b500::/32
    2405:8100::/32
    2a06:98c0::/29
    2c0f:f248::/32
)

start() {
    local non_interactive=${1:-0}
    
    # 检测可用的IP版本
    get_ipv4
    local has_ipv4=$?
    get_ipv6
    local has_ipv6=$?

    # 确定使用哪个IP版本
    if [ "$IP_VERSION" == "ipv4" ]; then
        if [ $has_ipv4 -eq 0 ]; then
            USE_IPV4=1
            USE_IPV6=0
        else
            echo -e "${red}无法获取IPv4地址，但指定了使用IPv4模式${re}"
            exit 1
        fi
    elif [ "$IP_VERSION" == "ipv6" ]; then
        if [ $has_ipv6 -eq 0 ]; then
            USE_IPV4=0
            USE_IPV6=1
        else
            echo -e "${red}无法获取IPv6地址，但指定了使用IPv6模式${re}"
            exit 1
        fi
    else
        # auto 模式
        if [ $non_interactive -eq 0 ]; then
            echo ""
            echo "检测到的网络支持:"
            [ $has_ipv4 -eq 0 ] && echo -e " - ${green}IPv4: ${ipv4_address} (域名: ${ipv4_domain})${re}"
            [ $has_ipv6 -eq 0 ] && echo -e " - ${green}IPv6: ${ipv6_address} (域名: ${ipv6_domain})${re}"
            echo ""
            echo "请选择使用的IP协议版本:"
            echo " 1. 仅使用 IPv4"
            echo " 2. 仅使用 IPv6"
            echo " 3. 同时使用 IPv4 和 IPv6"
            read -p "请输入选项 (1/2/3): " ip_choice
            
            case $ip_choice in
                1)
                    if [ $has_ipv4 -eq 0 ]; then
                        USE_IPV4=1
                        USE_IPV6=0
                    else
                        echo -e "${red}无法使用IPv4，该服务器不支持IPv4${re}"
                        exit 1
                    fi
                    ;;
                2)
                    if [ $has_ipv6 -eq 0 ]; then
                        USE_IPV4=0
                        USE_IPV6=1
                    else
                        echo -e "${red}无法使用IPv6，该服务器不支持IPv6${re}"
                        exit 1
                    fi
                    ;;
                3)
                    if [ $has_ipv4 -eq 0 ] && [ $has_ipv6 -eq 0 ]; then
                        USE_IPV4=1
                        USE_IPV6=1
                    else
                        echo -e "${red}无法同时使用IPv4和IPv6，该服务器不同时支持两者${re}"
                        exit 1
                    fi
                    ;;
                *)
                    echo -e "${red}无效的选项${re}"
                    exit 1
                    ;;
            esac
        else
            # 无交互模式，优先IPv4，其次IPv6
            if [ $has_ipv4 -eq 0 ]; then
                USE_IPV4=1
                USE_IPV6=0
            elif [ $has_ipv6 -eq 0 ]; then
                USE_IPV4=0
                USE_IPV6=1
            else
                echo -e "${red}无法获取IPv4或IPv6地址${re}"
                exit 1
            fi
        fi
    fi

    if [ $non_interactive -eq 1 ]; then
        echo -e "自动安装依赖包..."
        install sudo ss iptables dig printf shuf
    else
        echo -e "脚本所需依赖包 ${yellow}curl,sudo,ss,iptables,dig,printf,shuf ${re}"
        read -p "是否允许脚本自动安装以上所需的依赖包(Y): " install_apps
        install_apps=${install_apps^^}
        if [ "$install_apps" == "Y" ]; then
            install sudo ss iptables dig printf shuf
        fi
    fi

    # 配置 IPv4 转发
    if [ $USE_IPV4 -eq 1 ]; then
        echo "检查IPv4的流量转发功能"
        if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
            echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
            echo "IPv4的流量转发 成功添加"
        fi
        sudo sysctl -p
        echo "IPv4的流量转发 已开启"
    fi

    # 配置 IPv6 转发
    if [ $USE_IPV6 -eq 1 ]; then
        echo "检查IPv6的流量转发功能"
        if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
            echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
            echo "IPv6的流量转发 成功添加"
        fi
        sudo sysctl -p
        echo "IPv6的流量转发 已开启"
    fi

    # 获取 Cloudflare CDN 地址
    if [ $USE_IPV4 -eq 1 ]; then
        cf2ipv4s ip.sb time.is
        if [ ${#cf_ipv4s[@]} -eq 0 ]; then
            echo "未找到符合要求的Cloudflare IPv4地址"
            if [ $USE_IPV6 -eq 0 ]; then
                exit 1
            fi
        else
            random_ipv4=$(printf "%s\n" "${cf_ipv4s[@]}" | shuf -n 1)
            echo -e "成功获取 Cloudflare CDN 的IPv4地址: ${yellow}${random_ipv4}${re}"
        fi
    fi

    if [ $USE_IPV6 -eq 1 ]; then
        cf2ipv6s ip.sb time.is
        if [ ${#cf_ipv6s[@]} -eq 0 ]; then
            echo "未找到符合要求的Cloudflare IPv6地址"
            if [ $USE_IPV4 -eq 0 ]; then
                exit 1
            fi
        else
            random_ipv6=$(printf "%s\n" "${cf_ipv6s[@]}" | shuf -n 1)
            echo -e "成功获取 Cloudflare CDN 的IPv6地址: ${yellow}${random_ipv6}${re}"
        fi
    fi

    # 清除旧规则
    [ $USE_IPV4 -eq 1 ] && del_iptables
    [ $USE_IPV6 -eq 1 ] && del_ip6tables

    if [ $non_interactive -eq 1 ]; then
        local_port=$PORT_PARAM
    else
        read -p $'请输入你的ProxyIP的本地端口（默认 443）: ' local_port
        local_port=${local_port:-443}
    fi
    
    if ss -tuln | grep -q ":${local_port} "; then
        echo -e "${red}${local_port}端口已被占用，退出脚本。请自行检查${local_port}端口占用问题${re}"
        exit 1
    fi

    # 验证端口号是否有效
    if ! [[ "$local_port" =~ ^[0-9]+$ ]] || [ "$local_port" -lt 1 ] || [ "$local_port" -gt 65535 ]; then
        echo -e "${red}错误: 无效的端口号! 端口必须是1-65535之间的数字。${re}"
        return 1
    fi

    # 添加 IPv4 规则
    if [ $USE_IPV4 -eq 1 ] && [ -n "$random_ipv4" ]; then
        echo -e "添加 ${yellow}${random_ipv4}${re} 的IPv4 PREROUTING链中的${local_port}端口转发规则"
        
        # 添加特定来源IP的规则
        for ipv4_add in "${ipv4_addresses[@]}"; do
            sudo iptables -t nat -A PREROUTING -p tcp --dport $local_port -s "$ipv4_add" -j DNAT --to-destination ${random_ipv4}:443
        done
        
        sudo iptables -t nat -A POSTROUTING -j MASQUERADE
    fi
    
    # 添加 IPv6 规则
    if [ $USE_IPV6 -eq 1 ] && [ -n "$random_ipv6" ]; then
        echo -e "添加 ${yellow}${random_ipv6}${re} 的IPv6 PREROUTING链中的${local_port}端口转发规则"
        
        # 添加特定来源IP的规则
        for ipv6_add in "${ipv6_addresses[@]}"; do
            sudo ip6tables -t nat -A PREROUTING -p tcp --dport $local_port -s "$ipv6_add" -j DNAT --to-destination [$random_ipv6]:443
        done
        
        sudo ip6tables -t nat -A POSTROUTING -j MASQUERADE
    fi

    echo "保存防火墙规则"
    
    # 保存 IPv4 规则
    if [ $USE_IPV4 -eq 1 ]; then
        if [ ! -d "/etc/iptables" ]; then
            sudo mkdir -p /etc/iptables
        fi
        
        if sudo iptables-save > /tmp/rules.v4_temp && sudo mv /tmp/rules.v4_temp /etc/iptables/rules.v4; then
            echo "IPv4规则已成功保存到 /etc/iptables/rules.v4"
        else
            echo -e "${red}IPv4规则保存失败!${re}"
        fi
    fi
    
    # 保存 IPv6 规则
    if [ $USE_IPV6 -eq 1 ]; then
        if [ ! -d "/etc/iptables" ]; then
            sudo mkdir -p /etc/iptables
        fi
        
        if sudo ip6tables-save > /tmp/rules.v6_temp && sudo mv /tmp/rules.v6_temp /etc/iptables/rules.v6; then
            echo "IPv6规则已成功保存到 /etc/iptables/rules.v6"
        else
            echo -e "${red}IPv6规则保存失败!${re}"
        fi
    fi
    
    # 配置开机自动加载规则
    if [ -d "/etc/network/if-pre-up.d" ]; then
        echo "配置网络启动时自动加载规则"
        echo "#!/bin/sh" | sudo tee /etc/network/if-pre-up.d/iptables > /dev/null
        if [ $USE_IPV4 -eq 1 ]; then
            echo "[ -f /etc/iptables/rules.v4 ] && iptables-restore < /etc/iptables/rules.v4" | sudo tee -a /etc/network/if-pre-up.d/iptables > /dev/null
        fi
        if [ $USE_IPV6 -eq 1 ]; then
            echo "[ -f /etc/iptables/rules.v6 ] && ip6tables-restore < /etc/iptables/rules.v6" | sudo tee -a /etc/network/if-pre-up.d/iptables > /dev/null
        fi
        echo "exit 0" | sudo tee -a /etc/network/if-pre-up.d/iptables > /dev/null
        sudo chmod +x /etc/network/if-pre-up.d/iptables
    elif [ -d "/etc/systemd/system" ]; then
        echo "配置systemd服务自动加载规则"
        
        if [ $USE_IPV4 -eq 1 ]; then
            echo "[Unit]
Description=Restore iptables rules
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/iptables-restore.service > /dev/null
            sudo systemctl daemon-reload
            sudo systemctl enable iptables-restore.service
        fi
        
        if [ $USE_IPV6 -eq 1 ]; then
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
    fi
}

#########################梦开始的地方##############################

# 如果处于无交互模式，直接执行开启操作
if [ $NON_INTERACTIVE -eq 1 ]; then
    echo "检测到无交互参数 ${PORT_PARAM}，自动开启Cloudflare ProxyIP..."
    echo "你是否明白你当前的操作意味着什么？"
    echo -e "${purple}这个操作将会让你的IP成为反代IP库中的一份子，如果你的反代IP泄露或被人扫出来，你将会失去你全部流量！！！${re}"
    echo -e "${purple}请不要在生产力机器上执行这个脚本！更不要在绑定了你的信用卡的机器上运行这个脚本！${re}"
    start 1
    echo -e "${green}开启ProxyIP成功${re}"
    echo -e "端口:${yellow}${PORT_PARAM}${re}"
    [ $USE_IPV4 -eq 1 ] && echo -e "IPv4 ProxyIP: ${green}${ipv4_address}:${PORT_PARAM}${re}"
    [ $USE_IPV4 -eq 1 ] && echo -e "IPv4 ProxyIP域名: ${green}${ipv4_domain}:${PORT_PARAM}${re}"
    [ $USE_IPV6 -eq 1 ] && echo -e "IPv6 ProxyIP: ${green}[${ipv6_address}]:${PORT_PARAM}${re}"
    [ $USE_IPV6 -eq 1 ] && echo -e "IPv6 ProxyIP域名: ${green}${ipv6_domain}:${PORT_PARAM}${re}"
    exit 0
fi

while true; do
get_ipv4
get_ipv6
clear
echo -e "${yellow} ____                      ___ ____         __   ${re}"
echo -e "${yellow}|  _ \\ _ __ _____  ___   _|_ _|  _ \\__   __/ /_  ${re}"
echo -e "${yellow}| |_) | '__/ _ \\ \\/ / | | || || |_) \\ \\ / / '_ \\ ${re}"
echo -e "${yellow}|  __/| | | (_) >  <| |_| || ||  __/ \\ V /| (_) |${re}"
echo -e "${yellow}|_|   |_|  \\___/_/\\_\\\\__,  |___|_|     \\_/  \\___/ ${re}"
echo -e " 作者: cmliu         ${yellow}|___/${re} TG交流群: t.me/CMLiussss"    
echo "-------------------------------------------------------------------"
echo " 配置信息:" 
if [ -n "$ipv4_address" ]; then
    echo -e " IPv4:${green} ${ipv4_address}${re}"
    echo -e " IPv4 ProxyIP域名:${green} ${ipv4_domain}${re}"
fi
if [ -n "$ipv6_address" ]; then
    echo -e " IPv6:${green} [${ipv6_address}]${re}"
    echo -e " IPv6 ProxyIP域名:${green} ${ipv6_domain}${re}"
fi
echo "-------------------------------------------------------------------"
echo -e " 1. ${green}开启 Cloudflare ProxyIP ${re}"
echo -e " 2. ${purple}清除 Cloudflare ProxyIP 规则${re}"
echo "-------------------------------------------------------------------"
echo -e " 3. 查看 iptables 所有规则信息 (IPv4)"
echo -e " 4. 查看 ip6tables 所有规则信息 (IPv6)"
echo -e " 5. 清空 iptables 所有规则信息 (IPv4)"
echo -e " 6. 清空 ip6tables 所有规则信息 (IPv6)"
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
    read -p "你确定你要自行承担这个风险了吗？（Y/N 默认N）: " fxxkme
    fxxkme=${fxxkme^^}
    if [ "$fxxkme" == "Y" ]; then
        start 0
        echo -e "${green}开启ProxyIP成功${re}"
        [ $USE_IPV4 -eq 1 ] && echo -e "你的IPv4 ProxyIP: ${green}${ipv4_address}${re}"
        [ $USE_IPV4 -eq 1 ] && echo -e "你的IPv4 ProxyIP域名: ${green}${ipv4_domain}${re}"
        [ $USE_IPV6 -eq 1 ] && echo -e "你的IPv6 ProxyIP: ${green}[${ipv6_address}]${re}"
        [ $USE_IPV6 -eq 1 ] && echo -e "你的IPv6 ProxyIP域名: ${green}${ipv6_domain}${re}"
    fi
    ;;

  2)
    echo "清除 ProxyIP 规则..."
    del_iptables
    del_ip6tables
    echo -e "${green}规则已清除${re}"
    ;;

  3)
    echo "IPv4 iptables 规则:"
    sudo iptables -t nat -L -v -n
    ;;

  4)
    echo "IPv6 ip6tables 规则:"
    sudo ip6tables -t nat -L -v -n
    ;;

  5)
    read -p "这操作不单只是清空该脚本的规则，而是将 iptables 规则完全清空，你确定要执行吗（Y/N 默认N）: " fxxkiptables
    fxxkiptables=${fxxkiptables^^}
    if [ "$fxxkiptables" == "Y" ]; then
        sudo iptables -t nat -F
        echo -e "${green}IPv4 iptables规则已清空${re}"
    fi
    ;;

  6)
    read -p "这操作不单只是清空该脚本的规则，而是将 ip6tables 规则完全清空，你确定要执行吗（Y/N 默认N）: " fxxkip6tables
    fxxkip6tables=${fxxkip6tables^^}
    if [ "$fxxkip6tables" == "Y" ]; then
        sudo ip6tables -t nat -F
        echo -e "${green}IPv6 ip6tables规则已清空${re}"
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

