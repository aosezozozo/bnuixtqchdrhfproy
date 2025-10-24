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

#####################################################################
# 混淆防小人，不防君子，你要源码你直接和我说呀
# 而且解码其实也巨简单
# chmod 700 "$bztmp" 改成 chmod 700 "$bztmp" && cp "$bztmp" test.sh
# 就是这么简单，脚本本体就自己跑出来了
# 虽然不知道你是怎么解开的，但至少我是这么干的，如果你解开的方式不一样也可以交流一下。
#####################################################################

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
    ipv6_domain="ProxyIP.$(echo $ipv6_address | sed 's/:/-/g').ip.proy.pp.ua"

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

add_prerouting_rules() {
    for ipv6_add in "${ipv6_addresses[@]}"; do
        echo "添加 $random_ipv6 的PREROUTING链中的443端口转发规则 (仅允许 $ipv6_add)"
        sudo ip6tables -t nat -A PREROUTING -p tcp --dport 443 -s "$ipv6_add" -j DNAT --to-destination "[$random_ipv6]:443"
    done
}

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
echo "-------------------------------------------------------------------"
echo -e " 1. ${green}开启 Cloudflare ProxyIPv6 ${re}"
echo -e " 2. ${purple}清除 Cloudflare ProxyIPv6 ${re}"
echo "-------------------------------------------------------------------"
echo -e " 3. 查看 ip6tables 所有规则信息"
echo -e " 4. 清空 ip6tables 所有规则信息"
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
        echo -e "开启ProxyIP成功，你的IPv6_ProxyIP域名: ${green}${ipv6_domain}"
    fi
    ;;

  2)
    del_ip6tables
    ;;

  3)
    sudo ip6tables -t nat -L -v -n
    #sudo ip6tables -t filter -L INPUT -v -n
    ;;

  4)
    read -p "这操作不单只是清空该脚本的规则，而是将 ip6tables 规则完全清空，你确定要执行吗（Y/N 默认N）" fxxkip6tables
    fxxkip6tables=${fxxkip6tables^^} # 转换为大写
    if [ "$fxxkip6tables" == "Y" ]; then
        sudo ip6tables -t nat -F
    fi
    ;;

  0)
    clear
    exit
    ;;

  *)
    read -p "无效的输入!"
    ;;
esac
    break_end
done
