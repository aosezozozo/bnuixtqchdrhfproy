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
            echo -e"${red}暂不支持你的系统!${re}"
            return 1
        fi
    done

    return 0
}

# 配置 NAT64/DNS64 支持
setup_nat64() {
    clear
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}配置 NAT64/DNS64 支持${re}"
    echo -e "${cyan}======================================${re}"
    
    # NAT64 提供商列表（DNS64 服务器 + 网关）
    declare -A nat64_providers=(
        ["dns64.dns64.net"]="2001:67c:2b0::4|2001:67c:2b0::"
        ["nat64.xyz"]="2a01:4f9:c010:3f02::1|2a01:4f9:c010:3f02::"
        ["trex.fi"]="2001:67c:2960:6400::4|2001:67c:2960:6400::"
        ["go6lab.si"]="2001:67c:27e4:15::6411|2001:67c:27e4::"
    )
    
    echo -e "${yellow}正在测试可用的 NAT64 网关...${re}"
    echo ""
    
    working_gateway=""
    working_dns=""
    
    # 测试每个提供商
    for provider in "${!nat64_providers[@]}"; do
        IFS='|' read -r dns_server gateway <<< "${nat64_providers[$provider]}"
        
        echo -e "${cyan}测试 ${provider} (${dns_server})...${re}"
        
        # 测试 DNS64 解析
        test_result=$(dig AAAA ipv4only.arpa @${dns_server} +short +time=3 2>/dev/null | head -1)
        
        if [[ "$test_result" =~ ^64:ff9b:: ]]; then
            echo -e "${green}  ✓ DNS64 解析成功: ${test_result}${re}"
            
            # 测试实际连接
            if timeout 5 bash -c "cat < /dev/null > /dev/tcp/[64:ff9b::101:101]/443" 2>/dev/null; then
                echo -e "${green}  ✓ TCP 连接测试成功！${re}"
                working_gateway="$gateway"
                working_dns="$dns_server"
                break
            else
                echo -e "${yellow}  ✗ TCP 连接测试失败${re}"
            fi
        else
            echo -e "${red}  ✗ DNS64 解析失败${re}"
        fi
        echo ""
    done
    
    if [ -z "$working_gateway" ]; then
        echo -e "${red}======================================${re}"
        echo -e "${red}错误：没有找到可用的 NAT64 网关${re}"
        echo -e "${red}======================================${re}"
        echo ""
        echo "可能的原因："
        echo "1. 你的 VPS 提供商完全屏蔽了 NAT64 流量"
        echo "2. 你的 IPv6 网络配置有问题"
        echo ""
        echo "建议："
        echo "- 联系 VPS 提供商确认是否支持 NAT64"
        echo "- 或使用普通的 IPv6 代理（不使用 NAT64）"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    echo -e "${green}======================================${re}"
    echo -e "${green}找到可用的 NAT64 网关！${re}"
    echo -e "${green}======================================${re}"
    echo -e "DNS64 服务器: ${working_dns}"
    echo -e "NAT64 网关: ${working_gateway}"
    echo ""
    
    # 1. 备份原始 resolv.conf
    if [ ! -f /etc/resolv.conf.backup ]; then
        echo -e "${yellow}备份原始 DNS 配置...${re}"
        sudo cp /etc/resolv.conf /etc/resolv.conf.backup
    fi
    
    # 2. 配置 DNS64 解析器
    echo -e "${yellow}配置 DNS64 解析器...${re}"
    
    # 移除旧的 NAT64 配置
    sudo sed -i '/# NAT64/d' /etc/resolv.conf
    sudo sed -i '/2001:67c:2b0::4/d' /etc/resolv.conf
    sudo sed -i '/2a01:4f9:c010:3f02::1/d' /etc/resolv.conf
    sudo sed -i '/2001:67c:2960:6400::4/d' /etc/resolv.conf
    sudo sed -i '/2001:67c:27e4:15::6411/d' /etc/resolv.conf
    sudo sed -i '/2a01:4f8:c2c:123f::1/d' /etc/resolv.conf
    
    # 添加新的 DNS64
    sudo sed -i "1i# NAT64/DNS64 - $(date)" /etc/resolv.conf
    sudo sed -i "2i nameserver ${working_dns}" /etc/resolv.conf
    
    echo -e "${green}✓ DNS64 配置完成${re}"
    
    # 3. 添加 NAT64 路由
    echo -e "${yellow}配置 NAT64 路由...${re}"
    
    # 删除旧路由
    sudo ip -6 route del 64:ff9b::/96 2>/dev/null
    
    # 添加新路由（如果提供商指定了网关，使用 via；否则直接路由）
    if [ "$working_gateway" != "2001:67c:2b0::" ]; then
        sudo ip -6 route add 64:ff9b::/96 via ${working_gateway}1 2>/dev/null || \
        sudo ip -6 route add 64:ff9b::/96 dev $(ip -6 route get 2001:4860:4860::8888 | grep -oP 'dev \K\S+') 2>/dev/null
    else
        # dns64.dns64.net 不需要 via，直接路由
        sudo ip -6 route add 64:ff9b::/96 dev $(ip -6 route get 2001:4860:4860::8888 | grep -oP 'dev \K\S+') 2>/dev/null
    fi
    
    if ip -6 route | grep -q "64:ff9b::/96"; then
        echo -e "${green}✓ NAT64 路由配置完成${re}"
    else
        echo -e "${red}✗ NAT64 路由配置失败${re}"
    fi
    
    # 4. 持久化配置
    echo -e "${yellow}配置持久化（重启后自动生效）...${re}"
    
    # 创建启动脚本
    cat > /tmp/nat64-setup.sh << EOF
#!/bin/bash
# NAT64 自动配置脚本
sleep 5  # 等待网络就绪
ip -6 route del 64:ff9b::/96 2>/dev/null
ip -6 route add 64:ff9b::/96 dev \$(ip -6 route get 2001:4860:4860::8888 | grep -oP 'dev \K\S+') 2>/dev/null
EOF
    
    sudo mv /tmp/nat64-setup.sh /usr/local/bin/nat64-setup.sh
    sudo chmod +x /usr/local/bin/nat64-setup.sh
    
    # 创建 systemd 服务
    sudo tee /etc/systemd/system/nat64-setup.service > /dev/null << EOF
[Unit]
Description=NAT64 Route Setup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nat64-setup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    sudo systemctl enable nat64-setup.service 2>/dev/null
    
    echo -e "${green}✓ 持久化配置完成${re}"
    
    # 5. 最终验证
    echo ""
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}验证 NAT64 配置${re}"
    echo -e "${cyan}======================================${re}"
    
    echo -e "${yellow}测试 HTTP 访问...${re}"
    if curl -6 -s --max-time 5 -o /dev/null -w "%{http_code}" http://ipv4.google.com | grep -q "200\|301\|302"; then
        echo -e "${green}✓ NAT64 配置成功！可以访问 IPv4-only 网站！${re}"
    else
        echo -e "${yellow}✗ HTTP 测试失败，但 DNS64 可用，继续...${re}"
    fi
    
    echo ""
    echo -e "${green}======================================${re}"
    echo -e "${green}NAT64 配置完成！${re}"
    echo -e "${green}======================================${re}"
    echo "使用的 DNS64: ${working_dns}"
    echo "配置已持久化，重启后自动生效"
    
    read -p "按回车键返回主菜单..."
}

# 检查地址是否为 NAT64 地址
is_nat64() {
    local addr="$1"
    if [[ "$addr" =~ ^64:ff9b:: ]]; then
        return 0
    else
        return 1
    fi
}

# 将 IPv4 地址转换为 NAT64 地址
ipv4_to_nat64() {
    local ipv4="$1"
    # 分割 IPv4 地址
    IFS='.' read -r -a octets <<< "$ipv4"
    # 转换为十六进制并组合
    printf "64:ff9b::%02x%02x:%02x%02x" "${octets[0]}" "${octets[1]}" "${octets[2]}" "${octets[3]}"
}

# 将 NAT64 地址转换回 IPv4
nat64_to_ipv4() {
    local nat64="$1"
    # 提取后32位
    local suffix=$(echo "$nat64" | sed 's/64:ff9b:://')
    # 转换回 IPv4
    echo "$suffix" | awk -F: '{
        split($1, a, "");
        split($2, b, "");
        printf "%d.%d.%d.%d\n", 
            strtonum("0x"substr($1,1,2)), 
            strtonum("0x"substr($1,3,2)), 
            strtonum("0x"substr($2,1,2)), 
            strtonum("0x"substr($2,3,2))
    }'
}

# 获取 Cloudflare CDN 的 IPv6 和 IPv4 (NAT64) 地址
cf2ipv6s() {
    local domain
    cf_ipv6s=()
    cf_ipv6s_types=()  # 标记地址类型
    
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}获取 Cloudflare CDN 地址${re}"
    echo -e "${cyan}======================================${re}"
    
    for domain in "$@"; do
        echo -e "${yellow}查询域名: ${domain}${re}"
        
        # 获取真实 IPv6 地址
        echo -e "${cyan}  查询 IPv6 (AAAA记录)...${re}"
        ipv6s=($(dig AAAA "$domain" @2606:4700:4700::1111 +short 2>/dev/null | grep -E "$ipv6_regex"))
        if [ ${#ipv6s[@]} -gt 0 ]; then
            echo -e "${green}  ✓ 找到 ${#ipv6s[@]} 个 IPv6 地址${re}"
            for ipv6 in "${ipv6s[@]}"; do
                cf_ipv6s+=("$ipv6")
                cf_ipv6s_types+=("IPv6")
            done
        else
            echo -e "${yellow}  ✗ 未找到 IPv6 地址${re}"
        fi
        
        # 获取 IPv4 地址并转换为 NAT64
        echo -e "${cyan}  查询 IPv4 (A记录) 并转换为 NAT64...${re}"
        ipv4s=($(dig A "$domain" @1.1.1.1 +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'))
        if [ ${#ipv4s[@]} -gt 0 ]; then
            echo -e "${green}  ✓ 找到 ${#ipv4s[@]} 个 IPv4 地址，转换为 NAT64${re}"
            for ipv4 in "${ipv4s[@]}"; do
                nat64_addr=$(ipv4_to_nat64 "$ipv4")
                cf_ipv6s+=("$nat64_addr")
                cf_ipv6s_types+=("NAT64")
                echo -e "${cyan}    ${ipv4} → ${nat64_addr}${re}"
            done
        else
            echo -e "${yellow}  ✗ 未找到 IPv4 地址${re}"
        fi
        echo ""
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

    # 询问是否配置 NAT64
    if [ $non_interactive -eq 0 ]; then
        echo -e "${cyan}======================================${re}"
        echo -e "${yellow}NAT64 可以让你访问禁用了 IPv6 的 Cloudflare 网站${re}"
        echo -e "${yellow}通过 NAT64，你的纯 IPv6 VPS 可以访问 IPv4-only 的服务${re}"
        read -p $'是否配置 NAT64 支持？(Y/N 默认Y): ' enable_nat64
        enable_nat64=${enable_nat64^^}
        enable_nat64=${enable_nat64:-Y}
        
        if [ "$enable_nat64" == "Y" ]; then
            setup_nat64
            echo ""
        fi
    else
        setup_nat64
        echo ""
    fi

    # 获取 Cloudflare 地址
    cf2ipv6s ip.sb time.is cloudflare.com

    # 检查数组是否为空
    if [ ${#cf_ipv6s[@]} -eq 0 ]; then
        echo -e "${red}未找到任何可用的地址${re}"
        exit 1
    fi

    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}可用的 Cloudflare CDN 地址列表${re}"
    echo -e "${cyan}======================================${re}"
    
    # 显示所有可用地址
    for i in "${!cf_ipv6s[@]}"; do
        addr="${cf_ipv6s[$i]}"
        addr_type="${cf_ipv6s_types[$i]}"
        
        if [ "$addr_type" == "NAT64" ]; then
            # NAT64 地址，显示原始 IPv4
            original_ipv4=$(nat64_to_ipv4 "$addr")
            printf "${yellow}[%2d]${re} ${cyan}%-45s${re} ${purple}[NAT64]${re} ${skyblue}(原始: %s)${re}\n" "$((i+1))" "$addr" "$original_ipv4"
        else
            # 真实 IPv6 地址
            printf "${yellow}[%2d]${re} ${green}%-45s${re} ${white}[IPv6]${re}\n" "$((i+1))" "$addr"
        fi
    done
    echo -e "${cyan}======================================${re}"
    echo -e "${green}IPv6${re}  = 真实 IPv6 地址，直接通过 IPv6 网络访问"
    echo -e "${purple}NAT64${re} = IPv4 地址转换，通过 NAT64 网关访问 IPv4 服务"
    echo -e "${cyan}======================================${re}"

    if [ $non_interactive -eq 1 ]; then
        # 无交互模式，随机选择
        random_index=$((RANDOM % ${#cf_ipv6s[@]}))
        random_ipv6="${cf_ipv6s[$random_index]}"
        selected_type="${cf_ipv6s_types[$random_index]}"
    else
        # 交互模式，让用户选择
        while true; do
            read -p $'请选择要使用的地址编号 (1-'"${#cf_ipv6s[@]}"$', 或输入 0 随机选择): ' choice
            choice=${choice:-0}
            
            if [ "$choice" == "0" ]; then
                # 随机选择
                random_index=$((RANDOM % ${#cf_ipv6s[@]}))
                random_ipv6="${cf_ipv6s[$random_index]}"
                selected_type="${cf_ipv6s_types[$random_index]}"
                echo -e "${green}随机选择: [$((random_index+1))] ${random_ipv6} [${selected_type}]${re}"
                break
            elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#cf_ipv6s[@]}" ]; then
                # 用户选择
                random_ipv6="${cf_ipv6s[$((choice-1))]}"
                selected_type="${cf_ipv6s_types[$((choice-1))]}"
                echo -e "${green}你选择了: [$choice] ${random_ipv6} [${selected_type}]${re}"
                break
            else
                echo -e "${red}无效的选择，请重新输入！${re}"
            fi
        done
    fi

    # 显示选择的地址信息
    echo -e "${cyan}======================================${re}"
    if [ "$selected_type" == "NAT64" ]; then
        original_ipv4=$(nat64_to_ipv4 "$random_ipv6")
        echo -e "${green}已选择地址: ${random_ipv6}${re}"
        echo -e "${purple}类型: NAT64 (最终通过 IPv4 访问)${re}"
        echo -e "${skyblue}原始 IPv4: ${original_ipv4}${re}"
        echo -e "${yellow}此地址适用于禁用了 IPv6 的 Cloudflare 网站${re}"
    else
        echo -e "${green}已选择地址: ${random_ipv6}${re}"
        echo -e "${white}类型: 真实 IPv6${re}"
        echo -e "${yellow}此地址通过原生 IPv6 网络访问${re}"
    fi
    echo -e "${cyan}======================================${re}"

    del_ip6tables

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

# 清除 NAT64 配置
remove_nat64() {
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}清除 NAT64 配置${re}"
    echo -e "${cyan}======================================${re}"
    
    # 1. 恢复 DNS 配置
    if [ -f /etc/resolv.conf.bak ]; then
        sudo mv /etc/resolv.conf.bak /etc/resolv.conf
        echo -e "${green}已恢复原 DNS 配置${re}"
    else
        sudo sed -i '/# NAT64/d' /etc/resolv.conf
        sudo sed -i '/2a01:4f8:c2c:123f::1/d' /etc/resolv.conf
        sudo sed -i '/2a00:1098:2c::1/d' /etc/resolv.conf
        echo -e "${green}已移除 NAT64 DNS 配置${re}"
    fi
    
    # 2. 删除 NAT64 路由
    if ip -6 route | grep -q "64:ff9b::/96"; then
        sudo ip -6 route del 64:ff9b::/96 2>/dev/null
        echo -e "${green}已删除 NAT64 路由${re}"
    fi
    
    # 3. 删除持久化配置
    if [ -f /etc/network/if-up.d/nat64-route ]; then
        sudo rm /etc/network/if-up.d/nat64-route
        echo -e "${green}已删除 NAT64 路由持久化配置${re}"
    fi
    
    echo -e "${green}NAT64 配置已清除${re}"
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
echo -e " ${cyan}增强版: 支持 NAT64 (可访问 IPv4-only 网站)${re}"    
echo "-------------------------------------------------------------------"
echo " 配置信息:" 
echo -e " IPv6:${green} [${ipv6_address}]${re}"
echo -e " ProxyIP:${green} ${ipv6_domain}${re}"

# 检查 NAT64 状态
if ip -6 route | grep -q "64:ff9b::/96"; then
    echo -e " NAT64: ${green}已启用 ✓${re}"
else
    echo -e " NAT64: ${yellow}未启用${re}"
fi

echo "-------------------------------------------------------------------"
echo -e " 1. ${green}开启 Cloudflare ProxyIPv6 (支持选择地址)${re}"
echo -e " 2. ${purple}清除 Cloudflare ProxyIPv6 ${re}"
echo "-------------------------------------------------------------------"
echo -e " 3. ${cyan}配置 NAT64/DNS64 支持${re}"
echo -e " 4. ${cyan}清除 NAT64 配置${re}"
echo -e " 5. ${cyan}测试 NAT64 连接${re}"
echo "-------------------------------------------------------------------"
echo -e " 6. 查看 ip6tables 所有规则信息"
echo -e " 7. 清空 ip6tables 所有规则信息"
echo "-------------------------------------------------------------------"
echo -e "\033[0;97m 0. 退出脚本${re}" 
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
        echo ""
        echo -e "${green}======================================${re}"
        echo -e "${green}ProxyIP 开启成功！${re}"
        echo -e "${green}======================================${re}"
        echo -e "你的 IPv6 ProxyIP 域名: ${green}${ipv6_domain}${re}"
        
        if [ "$selected_type" == "NAT64" ]; then
            echo -e "${purple}使用的是 NAT64 地址，可访问禁用了 IPv6 的网站${re}"
        else
            echo -e "${white}使用的是真实 IPv6 地址${re}"
        fi
        echo -e "${green}======================================${re}"
    fi
    ;;

  2)
    del_ip6tables
    echo -e "${green}ProxyIP 规则已清除${re}"
    ;;

  3)
    setup_nat64
    ;;

  4)
    remove_nat64
    ;;

  5)
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}测试 NAT64 连接${re}"
    echo -e "${cyan}======================================${re}"
    
    if ! ip -6 route | grep -q "64:ff9b::/96"; then
        echo -e "${red}NAT64 路由未配置，请先执行选项 3 配置 NAT64${re}"
    else
        echo -e "${yellow}测试 1: Ping NAT64 地址${re}"
        echo -e "${cyan}目标: 64:ff9b::1.1.1.1 (Cloudflare DNS)${re}"
        if ping6 -c 3 -W 3 64:ff9b::1.1.1.1; then
            echo -e "${green}✓ Ping 测试成功${re}"
        else
            echo -e "${yellow}✗ Ping 测试失败（某些网关不响应 ping，这是正常的）${re}"
        fi
        
        echo ""
        echo -e "${yellow}测试 2: DNS64 解析测试${re}"
        echo -e "${cyan}查询 ipv4only.arpa (纯 IPv4 域名)${re}"
        result=$(dig AAAA ipv4only.arpa @2a01:4f8:c2c:123f::1 +short 2>/dev/null | head -1)
        if [[ "$result" =~ ^64:ff9b:: ]]; then
            echo -e "${green}✓ DNS64 工作正常${re}"
            echo -e "${green}  解析结果: ${result}${re}"
        else
            echo -e "${red}✗ DNS64 解析失败${re}"
        fi
        
        echo ""
        echo -e "${yellow}测试 3: HTTP 连接测试${re}"
        echo -e "${cyan}尝试通过 NAT64 访问 IPv4-only 网站${re}"
        if curl -6 -s --max-time 5 http://ipv4.google.com > /dev/null 2>&1; then
            echo -e "${green}✓ HTTP 连接测试成功${re}"
        else
            echo -e "${yellow}✗ HTTP 连接测试失败${re}"
        fi
    fi
    ;;

  6)
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}ip6tables NAT 表规则${re}"
    echo -e "${cyan}======================================${re}"
    sudo ip6tables -t nat -L -v -n
    echo ""
    echo -e "${cyan}======================================${re}"
    echo -e "${cyan}当前 IPv6 路由表${re}"
    echo -e "${cyan}======================================${re}"
    ip -6 route show
    ;;

  7)
    read -p "这操作不单只是清空该脚本的规则，而是将 ip6tables 规则完全清空，你确定要执行吗（Y/N 默认N）" fxxkip6tables
    fxxkip6tables=${fxxkip6tables^^} # 转换为大写
    if [ "$fxxkip6tables" == "Y" ]; then
        sudo ip6tables -t nat -F
        echo -e "${green}ip6tables NAT 规则已清空${re}"
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

