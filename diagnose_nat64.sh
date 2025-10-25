cat > diagnose_nat64.sh << 'EOF'
#!/bin/bash

echo "=========================================="
echo "NAT64 连接诊断"
echo "=========================================="
echo ""

# 1. 检查 IPv6 基础连接
echo "[1] 测试 IPv6 基础连接..."
if ping6 -c 3 2001:4860:4860::8888 > /dev/null 2>&1; then
    echo "✓ IPv6 连接正常"
else
    echo "✗ IPv6 连接失败！这是根本问题！"
    echo "  请先解决 IPv6 连接问题"
    exit 1
fi

# 2. 测试 DNS64 解析
echo ""
echo "[2] 测试 DNS64 解析..."
for dns in "2a00:1098:2c::1" "2001:67c:2b0::4" "2a01:4f9:c010:3f02::1"; do
    result=$(dig AAAA ipv4only.arpa @${dns} +short +time=2 2>/dev/null | head -1)
    if [[ -n "$result" ]]; then
        echo "✓ DNS64 ${dns} 可用: ${result}"
        WORKING_DNS="${dns}"
        break
    else
        echo "✗ DNS64 ${dns} 不可用"
    fi
done

if [ -z "$WORKING_DNS" ]; then
    echo ""
    echo "✗ 所有 DNS64 服务器都不可用！"
    echo "  可能原因："
    echo "  - VPS 提供商限制了外部 DNS 查询"
    echo "  - 防火墙阻止 UDP 53 端口"
    exit 1
fi

# 3. 测试 NAT64 转换后的地址
echo ""
echo "[3] 测试 NAT64 地址可达性..."

# 使用 DNS64 解析一个 IPv4-only 域名
nat64_addr=$(dig AAAA one.one.one.one @${WORKING_DNS} +short | head -1)
echo "解析 1.1.1.1 得到: ${nat64_addr}"

if [[ -z "$nat64_addr" ]]; then
    echo "✗ DNS64 无法解析 IPv4 地址"
    exit 1
fi

# 4. 测试不同协议的连接
echo ""
echo "[4] 测试连接能力..."

# ICMP (ping)
echo -n "ICMP (ping): "
if ping6 -c 2 -W 3 ${nat64_addr} > /dev/null 2>&1; then
    echo "✓ 可达"
else
    echo "✗ 不可达"
fi

# TCP 443 (nc 方式)
echo -n "TCP 443 (nc): "
if timeout 5 nc -6 -zv ${nat64_addr} 443 2>&1 | grep -q "succeeded\|open"; then
    echo "✓ 可连接"
else
    echo "✗ 连接失败"
fi

# TCP 443 (bash 方式)
echo -n "TCP 443 (bash): "
if timeout 5 bash -c "cat < /dev/null > /dev/tcp/[${nat64_addr}]/443" 2>/dev/null; then
    echo "✓ 可连接"
else
    echo "✗ 连接失败"
fi

# HTTP 80
echo -n "TCP 80 (http): "
if timeout 5 bash -c "cat < /dev/null > /dev/tcp/[${nat64_addr}]/80" 2>/dev/null; then
    echo "✓ 可连接"
else
    echo "✗ 连接失败"
fi

# 5. 测试 curl
echo ""
echo "[5] 测试实际 HTTP 请求..."
echo -n "curl -6 ipv4.google.com: "
http_code=$(curl -6 -s --max-time 8 -o /dev/null -w "%{http_code}" http://ipv4.google.com 2>/dev/null)
if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
    echo "✓ 成功 (${http_code})"
else
    echo "✗ 失败 (${http_code})"
fi

# 6. 检查防火墙
echo ""
echo "[6] 检查防火墙规则..."
if command -v ip6tables > /dev/null; then
    forward_policy=$(ip6tables -L FORWARD -n 2>/dev/null | grep "policy" | awk '{print $4}')
    echo "IPv6 FORWARD 策略: ${forward_policy:-未知}"
    
    if [[ "$forward_policy" == "DROP" ]] || [[ "$forward_policy" == "REJECT" ]]; then
        echo "✗ 防火墙可能阻止了 NAT64 转发！"
        echo ""
        echo "尝试临时允许："
        echo "  sudo ip6tables -P FORWARD ACCEPT"
    fi
fi

# 7. 检查路由表
echo ""
echo "[7] 当前 IPv6 路由..."
ip -6 route | grep -E "64:ff9b|2001:67c:2b0|2a01:4f9:c010|2a01:4f8:c2c|2a00:1098:2c|2001:67c:2960|2602:fc59"

# 8. VPS 提供商检测
echo ""
echo "[8] VPS 提供商信息..."
if curl -s --max-time 3 ipinfo.io 2>/dev/null | grep -q "org"; then
    org=$(curl -s --max-time 3 ipinfo.io 2>/dev/null | grep "org" | cut -d'"' -f4)
    echo "提供商: ${org}"
fi

echo ""
echo "=========================================="
echo "诊断完成"
echo "=========================================="
EOF

chmod +x diagnose_nat64.sh
./diagnose_nat64.sh
