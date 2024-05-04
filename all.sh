#!/bin/bash

export red='\033[31m'
export cyan='\033[36m'
export reset_color='\033[0m'

#初始化系统
initialization() {

# 检测操作系统类型
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
fi

#安装基础软件
if [[ "$ID" == "centos"* ]]; then
    yum update -y
    packages=("nginx" "socat" "curl" "gnupg" "sudo")
    for pkg in "${packages[@]}"; do
        if ! rpm -q "$pkg" &>/dev/null; then
            yum install "$pkg" -y
        fi
    done
    systemctl start nginx
    systemctl enable nginx
elif [[ "$ID" == "debian"* ]] || [[ "$ID" == "ubuntu"* ]]; then
    apt-get update -y
    packages=("nginx" "socat" "curl" "gnupg" "sudo")
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            apt-get install "$pkg" -y
        fi
    done
    systemctl enable nginx
else
    echo -e "${red} 该脚本仅支持 CentOS、Debian 和 Ubuntu ${reset_color}"
    exit 1
fi
}

#xray搭建
installXray() {

#安装xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root

#配置config.json
uuid=$(xray uuid)
echo -n -e "${cyan}是否需要安装Warp？(输入 y 或 n): ${reset_color}"
read install_warp

if [ "$install_warp" = "y" ]; then
echo -n -e "${cyan}请输入Warp端口号: ${reset_color}"
read warpport
fi
# 删除config.json文件中的所有内容
> /usr/local/etc/xray/config.json
cat << EOF >> /usr/local/etc/xray/config.json
{
    "log": {
        "loglevel": "warning"
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:cn",
                    "geoip:private"
                ],
                "outboundTag": "block"
            },
            {
	            "type": "field",
	            "domain": [
	            	"geosite:openai",
		            "geosite:disney",
		            "geosite:netflix"
	            ],
	            "outboundTag": "warp"
            }
        ]
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$uuid", 
                        "flow": "xtls-rprx-vision",
                        "level": 0
                    }
                ],
                "decryption": "none",
                "fallbacks": [
                    {
                        "dest": "8001",
                        "xver": 1
                    },
                    {
                        "alpn": "h2",
                        "dest": "8002",
                        "xver": 1
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "rejectUnknownSni": true,
                    "minVersion": "1.2",
                    "alpn": [
                        "http/1.1",
                        "h2"
                    ],
                    "certificates": [
                        {
                            "ocspStapling": 3600,
                            "certificateFile": "/usr/local/etc/ssl/xray.crt",
                            "keyFile": "/usr/local/etc/ssl/xray.key"
                        }
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                 ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        },
        {
            "protocol": "socks",
            "settings": {
            "servers": [{
            "address": "127.0.0.1",
            "port": $warpport
            }]
        },
            "tag": "warp"
     
        }
    ]
}
EOF

# 安装WARP
if [ "$install_warp" = "y" ]; then
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
    fi
    if [[ "$ID" == "debian"* ]]; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
        sudo apt-get update
        sudo apt-get install cloudflare-warp -y
    elif [[ "$ID" == "ubuntu"* ]]; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
        sudo apt-get update
        sudo apt-get install cloudflare-warp -y
    elif [[ "$ID" == "centos"* ]]; then
        curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo | sudo tee /etc/yum.repos.d/cloudflare-warp.repo
        sudo yum update
        sudo yum install cloudflare-warp -y
    else
        echo -e "${red} 该脚本仅支持 CentOS、Debian 和 Ubuntu ${reset_color}"
        exit 1
    fi
    
    echo -e "${cyan} 请输入Warp登陆模式: ${reset_color}"
    echo -e "${cyan} 1: Warp+ Key ${reset_color}" 
    echo -e "${cyan} 2: Zero Trust ${reset_color}"
    echo -n -e "${cyan} 请选择: ${reset_color}"
    read choice

    case $choice in
        1)
            echo -e "${cyan} 您选择了 Warp+ Key ${reset_color}"
            warp-cli register
            echo -n -e "${cyan}请输入Warp+ Key: ${reset_color}"
            read warpkey
            warp-cli set-license $warpkey
            warp-cli set-mode proxy
            warp-cli set-proxy-port $warpport
            warp-cli connect
            ;;
        2)
            echo -e "${cyan} 您选择了 Zero Trust ${reset_color}"
            echo -n -e "${cyan} 请输入您的团队名: ${reset_color}"
            read teamname
            warp-cli teams-enroll $teamname
            echo -e "${cyan}******************************************************************************${reset_color}"
            echo -e "${cyan}复制 “A browser window should open at the following URL:” 下面的链接在浏览器中打开${reset_color}"
            echo -e "${cyan}******************************************************************************${reset_color}"
            echo -e "${cyan}在成功页面上，右键单击并选择“查看页面源”,复制URL字段：com.cloudflare.warp.....${reset_color}"
            echo -e "${cyan}******************************************************************************${reset_color}"
            echo -n -e "${cyan}请输入token: ${reset_color}"
            read token
            warp-cli teams-enroll-token $token
            warp-cli connect
            warp-cli account
            ;;
        *)
            echo -e "${red} 无效的选择 ${reset_color}"
            ;;
    esac
fi

mkdir /usr/local/etc/cloudreve
wget https://github.com/cloudreve/Cloudreve/releases/download/3.8.3/cloudreve_3.8.3_linux_amd64.tar.gz
tar -zxvf cloudreve_3.8.3_linux_amd64.tar.gz -C /usr/local/etc/cloudreve/
chmod +x /usr/local/etc/cloudreve/cloudreve
flag=false
/usr/local/etc/cloudreve/cloudreve > /usr/local/etc/cloudreve/output.txt & cloudreve_pid=$!
sleep 5
if [ "$flag" = true ]; then
    kill $cloudreve_pid
fi

# 获取Cloudreve初始管理员账号、密码和端口号
admin_user=$(grep -oP 'Admin user name: \K\S+' /usr/local/etc/cloudreve/output.txt)
admin_pass=$(grep -oP 'Admin password: \K\S+' /usr/local/etc/cloudreve/output.txt)
admin_port=$(grep -oP 'Listening to \K\S+' /usr/local/etc/cloudreve/output.txt)

# 输出默认账号、密码和端口号
echo -e "${cyan}*********************************${reset_color}"
echo -e "${cyan}初始管理员账号：$admin_user${reset_color}"
echo -e "${cyan}初始管理员密码：$admin_pass${reset_color}"
echo -e "${cyan}初始端口号：$admin_port${reset_color}"
echo -e "${cyan}*********************************${reset_color}"
echo -e "${cyan}请保存账号、密码、端口号后按回车键继续...${reset_color}"
read -p ""

# 配置Cloudreve systemd服务
cat << EOF >> /usr/lib/systemd/system/cloudreve.service
[Unit]
Description=Cloudreve
Documentation=https://docs.cloudreve.org
After=network.target
After=mysqld.service
Wants=network.target

[Service]
WorkingDirectory=/usr/local/etc/cloudreve
ExecStart=/usr/local/etc/cloudreve/cloudreve
Restart=on-abnormal
RestartSec=5s
KillMode=mixed

StandardOutput=null
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cloudreve
systemctl start cloudreve
    
#删除output.txt
rm /usr/local/etc/cloudreve/output.txt
    
#删除cloudreve tar包
rm cloudreve_3.8.3_linux_amd64.tar.gz

mkdir /usr/local/etc/ssl
#检测acme
if command -v ~/.acme.sh/acme.sh &> /dev/null
then
    echo -e "${cyan}acme已安装，跳过... ${reset_color}"
else
    curl https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
fi
#设置dns服务商
echo -e "${cyan} 请选择域名DNS服务商: ${reset_color}"
echo -e "${cyan} 1: Dnspod ${reset_color}"
echo -e "${cyan} 2: Cloudflare ${reset_color}"
echo -e "${cyan} 3: Aliyun ${reset_color}"
echo -e "${cyan} 4: Google ${reset_color}"
echo -n -e "${cyan} 请选择: ${reset_color}"
read choice
case $choice in
    1)
        echo -e "${cyan} 您选择了Dnspod ${reset_color}"
        echo -n -e "${cyan}请输入ID: ${reset_color}"
        read id
        echo -n -e "${cyan}请输入KEY: ${reset_color}"
        read key
        export DP_Id="$id"
        export DP_Key="$key"
        echo -n -e "${cyan} 请输入域名: ${reset_color}"
        read domain
        ~/.acme.sh/acme.sh --issue --dns dns_dp -d $domain -k ec-256
        ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
            --fullchain-file /usr/local/etc/ssl/xray.crt \
            --key-file /usr/local/etc/ssl/xray.key --reloadcmd "systemctl force-reload xray"
        ;;
    2)
        echo -e "${cyan} 您选择了Cloudflare ${reset_color}"
        echo -n -e "${cyan}请输入KEY: ${reset_color}"
        read key
        echo -n -e "${cyan}请输入EMAIL: ${reset_color}"
        read email
        export CF_Key="$key"
        export CF_Email="$email"
        echo -n -e "${cyan} 请输入域名: ${reset_color}"
        read domain
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d $domain -k ec-256
        ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
            --fullchain-file /usr/local/etc/ssl/xray.crt \
            --key-file /usr/local/etc/ssl/xray.key --reloadcmd "systemctl force-reload xray"
        ;;
    3)
        echo -e "${cyan} 您选择了Aliyun ${reset_color}"
        echo -n -e "${cyan}请输入KEY: ${reset_color}"
        read key
        echo -n -e "${cyan}请输入SECRET: ${reset_color}"
        read secret
        export Ali_Key="$key"
        export Ali_Secret="$secret"
        echo -n -e "${cyan} 请输入域名: ${reset_color}"
        read domain
        ~/.acme.sh/acme.sh --issue --dns dns_ali -d $domain -k ec-256
        ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
            --fullchain-file /usr/local/etc/ssl/xray.crt \
            --key-file /usr/local/etc/ssl/xray.key --reloadcmd "systemctl force-reload xray"
        ;;
    4)
        echo -e "${cyan} 您选择了Google ${reset_color}"
        echo -n -e "${cyan}请输入API令牌: ${reset_color}"
        read api
        export GOOGLEDOMAINS_ACCESS_TOKEN="$api"
        echo -n -e "${cyan} 请输入域名: ${reset_color}"
        read domain
        ~/.acme.sh/acme.sh --issue --dns dns_googledomains -d $domain -k ec-256
        ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
            --fullchain-file /usr/local/etc/ssl/xray.crt \
            --key-file /usr/local/etc/ssl/xray.key --reloadcmd "systemctl force-reload xray"
        ;;
    *)
        echo -e "${red} 无效的选择 ${reset_color}"
        ;;
esac
    
#nginx反代
> /etc/nginx/nginx.conf
cat << EOF >> /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 1024;
	# multi_accept on;
}
http {
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ''      close;
    }
    server {
        listen 127.0.0.1:8001 proxy_protocol;
        listen 127.0.0.1:8002 http2 proxy_protocol;
        server_name  $domain;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        add_header Strict-Transport-Security "max-age=31536000";
        error_page 497  https://\$host\$request_uri;

        location / {
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header REMOTE-HOST \$remote_addr;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
            proxy_pass http://127.0.0.1:5212;

            add_header X-Cache \$upstream_cache_status;

            set \$static_filerDMgmXdG 0;
            if ( \$uri ~* "\.(gif|png|jpg|css|js|woff|woff2)$" ) {
                set \$static_filerDMgmXdG 1;
                expires 1m;
            }
            if ( \$static_filerDMgmXdG = 0 ) {
                add_header Cache-Control no-cache;
            }
        }
    }
    server {
        listen  80;
        return 301 https://\$http_host\$request_uri;
    }
}
EOF

# 安装BBR
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

#重启服务
systemctl restart nginx
systemctl restart xray
systemctl restart cloudreve

encoded_uuid=$(echo -n "auto:$uuid@$domain:443" | base64)
echo -e "${cyan}*************************************************************************************${reset_color}"
echo -e "${cyan}warp端口号：$warpport${reset_color}"
echo -e "${cyan}Zero Trust代理及端口号修改步骤：Zero Trust - Settings - WARP Client - Device settings(点击Default后面三个点，选择Configure) - Service mode(代理选择Proxy mode 端口号修改Port: Edit)${reset_color}"
echo -e "${cyan}*************************************************************************************${reset_color}"
echo -e "${cyan}Shadowrocket链接：vless://$encoded_uuid?obfs=none&tls=1&peer=$domain&xtls=2${reset_color}"
echo -e "${cyan}*************************************************************************************${reset_color}"
echo -e "${cyan}Passwall链接：vless://$uuid@$domain:443?headerType=none&type=tcp&encryption=none&fp=randomized&flow=xtls-rprx-vision&security=tls&sni=$domain#备注${reset_color}"
echo -e "${cyan}*************************************************************************************${reset_color}"
}

#安装Alist
installAlist() {
    curl -fsSL "https://alist.nn.ci/v3.sh" | bash -s install
}

while true; do
    echo -e "${cyan}******************** All In One 脚本 ********************${reset_color}"
    echo -e "${cyan}*                   1.初始化系统${reset_color}"         
    echo -e "${cyan}*                   2.Xray节点搭建${reset_color}"
    echo -e "${cyan}*                   3.Alist搭建${reset_color}"
    echo -e "${cyan}*                   4.退出${reset_color}"
    echo -e "${cyan}*********************************************************${reset_color}"
    echo -n -e "${cyan}请选择: ${reset_color}"
    read option
    case ${option} in
    1)
        initialization
        ;;
    2)
        installXray
        ;;
    3)
        installAlist
        ;;
    4)
        exit 0
        ;;
    *)
        echo -e "${red}无效的选择，请重新输入！${reset_color}"
        ;;
    esac
done
