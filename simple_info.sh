# =============== 通用设置 ===============
# 定义颜色
re='\e[0m'
red='\e[1;91m'
white='\e[1;97m'
green='\e[1;32m'
yellow='\e[1;33m'
purple='\e[1;35m'
skyblue='\e[1;96m'
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"
_red() { echo -e "\033[31m\033[01m$@\033[0m"; }
_green() { echo -e "\033[32m\033[01m$@\033[0m"; }
_yellow() { echo -e "\033[33m\033[01m$@\033[0m"; }
_blue() { echo -e "\033[36m\033[01m$@\033[0m"; }

break_end() {
    echo -e "${green}执行完成${re}"
    echo -e "${yellow}按任意键返回...${re}"
    read -n 1 -s -r -p ""
    echo ""
    clear
}
# 返回主菜单
main_menu() {
    cd ~
    ./ssh_tool.sh
    exit
}
# ===============  标头  ===============
while true; do
echo "--------------------- A VPS Simple Info Script By windtrace ----------------------"
echo "没啥好说的了，还在完善中..."
echo "Update：2024.01.19"

echo "-------------------------------------------------------------------"
echo -e "${green} 1. 本机信息"
echo -e "${green} 2. 系统更新"
echo -e "${green} 3. 系统清理"
echo -e "${green} 4. 组件管理 ▶${purple} "

echo "-------------------------------------------------------------------"
echo -e "${green}9. 脚本更新${red}                  0. 退出脚本${re}"
echo -e "${yellow}-------------------------------------------------------------------${re}"
read -p $'\033[1;91m请输入你的选择: \033[0m' choice
case $choice in
	1)
	clear
	# =============== 本机信息 ===============
	echo -e "\n--------------------- System Info ----------------------"
	#主机名
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "主机名称" $(hostname)
	# 运营商
	isp_info=$(curl -s ipinfo.io/org)
	printf "%-19s:\e[30;96m %-40s\n\e[0m" "运营商" "${isp_info}"
	#系统版本
	# 尝试使用 lsb_release 获取系统信息
	os_info=$(lsb_release -ds 2>/dev/null)
	# 如果 lsb_release 命令失败，则尝试其他方法
	if [ -z "$os_info" ]; then
	# 检查常见的发行文件
	 if [ -f "/etc/os-release" ]; then
	  os_info=$(source /etc/os-release && echo "$PRETTY_NAME")
	 elif [ -f "/etc/debian_version" ]; then
	  os_info="Debian $(cat /etc/debian_version)"
	 elif [ -f "/etc/redhat-release" ]; then
	  os_info=$(cat /etc/redhat-release)
	else
	 os_info="Unknown"
	  fi
	fi
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "系统版本" "${os_info}"
	# Linux核心版本
	kernel_version=$(uname -r)
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "核心版本" "${kernel_version}"
	# -> 系统信息模块 (Collector) -> 获取虚拟化信息
	function BenchAPI_Systeminfo_GetVMMinfo() {
	    if [ -f "/usr/bin/systemd-detect-virt" ]; then
	        local r_vmmtype && r_vmmtype="$(/usr/bin/systemd-detect-virt 2>/dev/null)"
	        case "${r_vmmtype}" in
	        kvm)
	            Result_Systeminfo_VMMType="KVM"
	            Result_Systeminfo_VMMTypeShort="kvm"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        xen)
	            Result_Systeminfo_VMMType="Xen Hypervisor"
	            Result_Systeminfo_VMMTypeShort="xen"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        microsoft)
	            Result_Systeminfo_VMMType="Microsoft Hyper-V"
	            Result_Systeminfo_VMMTypeShort="microsoft"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        vmware)
	            Result_Systeminfo_VMMType="VMware"
	            Result_Systeminfo_VMMTypeShort="vmware"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        oracle)
	            Result_Systeminfo_VMMType="Oracle VirtualBox"
	            Result_Systeminfo_VMMTypeShort="oracle"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        parallels)
	            Result_Systeminfo_VMMType="Parallels"
	            Result_Systeminfo_VMMTypeShort="parallels"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        qemu)
	            Result_Systeminfo_VMMType="QEMU"
	            Result_Systeminfo_VMMTypeShort="qemu"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        amazon)
	            Result_Systeminfo_VMMType="Amazon Virtualization"
	            Result_Systeminfo_VMMTypeShort="amazon"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        docker)
	            Result_Systeminfo_VMMType="Docker"
	            Result_Systeminfo_VMMTypeShort="docker"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        openvz)
	            Result_Systeminfo_VMMType="OpenVZ (Virutozzo)"
	            Result_Systeminfo_VMMTypeShort="openvz"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        lxc)
	            Result_Systeminfo_VMMTypeShort="lxc"
	            Result_Systeminfo_VMMType="LXC"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        lxc-libvirt)
	            Result_Systeminfo_VMMType="LXC (Based on libvirt)"
	            Result_Systeminfo_VMMTypeShort="lxc-libvirt"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        uml)
	            Result_Systeminfo_VMMType="User-mode Linux"
	            Result_Systeminfo_VMMTypeShort="uml"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        systemd-nspawn)
	            Result_Systeminfo_VMMType="Systemd nspawn"
	            Result_Systeminfo_VMMTypeShort="systemd-nspawn"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        bochs)
	            Result_Systeminfo_VMMType="BOCHS"
	            Result_Systeminfo_VMMTypeShort="bochs"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        rkt)
	            Result_Systeminfo_VMMType="RKT"
	            Result_Systeminfo_VMMTypeShort="rkt"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        zvm)
	            Result_Systeminfo_VMMType="S390 Z/VM"
	            Result_Systeminfo_VMMTypeShort="zvm"
	            Result_Systeminfo_isPhysical="0"
	            return 0
	            ;;
	        none)
	            Result_Systeminfo_VMMType="Dedicated"
	            Result_Systeminfo_VMMTypeShort="none"
	            Result_Systeminfo_isPhysical="1"
	            if test -f "/sys/class/iommu/dmar0/uevent"; then
	                Result_Systeminfo_IOMMU="1"
	            else
	                Result_Systeminfo_IOMMU="0"
	            fi
	            return 0
	            ;;
	        *)
	            echo -e "${Msg_Error} BenchAPI_Systeminfo_GetVirtinfo(): invalid result (${r_vmmtype}), please check parameter!"
	            ;;
	        esac
	    fi
	    if [ -f "/.dockerenv" ]; then
	        Result_Systeminfo_VMMType="Docker"
	        Result_Systeminfo_VMMTypeShort="docker"
	        Result_Systeminfo_isPhysical="0"
	        return 0
	    elif [ -c "/dev/lxss" ]; then
	        Result_Systeminfo_VMMType="Windows Subsystem for Linux"
	        Result_Systeminfo_VMMTypeShort="wsl"
	        Result_Systeminfo_isPhysical="0"
	        return 0
	    else
	        Result_Systeminfo_VMMType="Dedicated"
	        Result_Systeminfo_VMMTypeShort="none"
	        if test -f "/sys/class/iommu/dmar0/uevent"; then
	            Result_Systeminfo_IOMMU="1"
	        else
	            Result_Systeminfo_IOMMU="0"
	        fi
	        return 0
	    fi
	}
	BenchAPI_Systeminfo_GetVMMinfo
	printf "%-21s:\e[30;96m %-10s\n\e[0m" "虚拟化架构" "${Result_Systeminfo_VMMType}"
	# 时间
	current_time=$(date "+%Y-%m-%d %I:%M %p")
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "系统时间" "${current_time}"

	up=$(awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60} {printf("%d days, %d hour %d min\n",a,b,c)}' /proc/uptime)
	printf "%-23s:\e[30;96m %-10s\n\e[0m" "系统在线时间" "${up}"

	load=$(
		LANG=C
		uptime | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//'
	)
	printf "%-18s:\e[30;96m %-10s\n\e[0m" "负载" "${load}"

	echo -e "\n--------------------- CPU Info ----------------------"
	# CPU架构
	cpu_arch=$(uname -m)
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "CPU架构" "${cpu_arch}"
	#  CPU 型号
	cname=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "CPU型号" "${cname}"
	# CPU核心数
	cpu_cores=$(nproc)
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "CPU核心" "${cpu_cores}"

	freq=$(awk -F'[ :]' '/cpu MHz/ {print $4;exit}' /proc/cpuinfo)
	printf "%-20s:\e[30;96m %-10s MHz\n\e[0m" "CPU频率" "${freq}"

	ccache=$(awk -F: '/cache size/ {cache=$2} END {print cache}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "CPU缓存" "${ccache}"
	CPU_AES=$(cat /proc/cpuinfo | grep aes)
	[[ -z "$CPU_AES" ]] && CPU_AES="\xE2\x9D\x8C Disabled" || CPU_AES="Enabled"
	printf "%-21s:\e[30;96m %-10s\n\e[0m" "AES-NI指令集 " "${CPU_AES}"

	CPU_VIRT=$(cat /proc/cpuinfo | grep 'vmx\|svm')
	[[ -z "$CPU_VIRT" ]] && CPU_VIRT="\xE2\x9D\x8C Disabled" || CPU_VIRT="Enabled"
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "VM-x/AMD-V支持" "${CPU_VIRT}"

	echo -e "\n--------------------- Memory & Disk Info ----------------------"
	# 物理内存
	mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "物理内存" "${mem_info}"

	#虚拟内存
	swap_used=$(free -m | awk 'NR==3{print $3}')
	    swap_total=$(free -m | awk 'NR==3{print $2}')
	    if [ "$swap_total" -eq 0 ]; then
	        swap_percentage=0
	    else
	        swap_percentage=$((swap_used * 100 / swap_total))
	    fi
	    swap_info="${swap_used}MB/${swap_total}MB (${swap_percentage}%)"
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "虚拟内存" "${swap_info}"

	# 硬盘
	disk_info=$(df -h | awk '$NF=="/"{printf "%d/%dGB (%s)", $3,$2,$5}')
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "硬盘占用" "${disk_info}"

	echo -e "\n--------------------- NetWork Info ----------------------"
	# 网络流量
	    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
	        NR > 2 { rx_total += $2; tx_total += $10 }
	        END {
	            rx_units = "Bytes";
	            tx_units = "Bytes";
	            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
	            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
	            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }
	            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
	            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
	            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }
	            printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
	        }' /proc/net/dev)

	echo -e "${purple}$output${re}"
	# 网络拥堵算法
	congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
	queue_algorithm=$(sysctl -n net.core.default_qdisc)
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "网络拥堵算法" "${congestion_algorithm} ${queue_algorithm}"

	# IP地址
	ipv4_address=$(curl -s ipv4.ip.sb)
	ipv6_address=$(curl -s --max-time 2 ipv6.ip.sb)
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "公网IPv4地址" "${ipv4_address}"
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "公网IPv6地址" "${ipv6_address}"

	# IP位置
	country=$(curl -s ipinfo.io/country)
	city=$(curl -s ipinfo.io/city)
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "地理位置" "${country} $city$"

	#
	check_ip_info_by_cloudflare() {
	    # cloudflare.com
	    rm -rf /tmp/cloudflare
	    # 获取 IPv4 信息
	    local ipv4_output=$(curl -ksL4m6 -A Mozilla https://speed.cloudflare.com/meta 2>/dev/null)
	    # 提取 IPv4 的 asn、asOrganization、city 和 region
	    local ipv4_asn=$(echo "$ipv4_output" | grep -oE '"asn":[0-9]+' | grep -oE '[0-9]+')
	    local ipv4_as_organization=$(echo "$ipv4_output" | grep -oE '"asOrganization":"[^"]+"' | grep -oE '":"[^"]+"' | sed 's/":"//g')
	    local ipv4_city=$(echo "$ipv4_output" | grep -oE '"city":"[^"]+"' | grep -oE '":"[^"]+"' | sed 's/":"//g')
	    local ipv4_region=$(echo "$ipv4_output" | grep -oE '"region":"[^"]+"' | grep -oE '":"[^"]+"' | sed 's/":"//g')
	    if [ -n "$ipv4_asn" ] && [ -n "$ipv4_as_organization" ] && [ -n "$ipv4_city" ] && [ -n "$ipv4_region" ]; then
	        local ipv4_asn_info="AS${ipv4_asn} ${ipv4_as_organization}"
	        local ipv4_location="${ipv4_city} / ${ipv4_region}"
	    else
	        local ipv4_asn_info="None"
	        local ipv4_location="None"
	    fi
	    # 去除双引号
	    if [[ $ipv4_asn_info == *"\""* ]]; then
	        ipv4_asn_info="${ipv4_asn_info//\"/}"
	    fi
	    if [[ $ipv4_location == *"\""* ]]; then
	        ipv4_location="${ipv4_location//\"/}"
	    fi
	    # 返回结果
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "IPV4 ASN" "${ipv4_asn_info}"
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "IPV4 Location" "${ipv4_location}"
	    # 获取 IPv6 信息
	    sleep 1
	    local ipv6_output=$(curl -ksL6m6 -A Mozilla https://speed.cloudflare.com/meta 2>/dev/null)
	    # 提取 IPv6 的 asn、asOrganization、city 和 region
	    local ipv6_asn=$(echo "$ipv6_output" | grep -oE '"asn":[0-9]+' | grep -oE '[0-9]+')
	    local ipv6_as_organization=$(echo "$ipv6_output" | grep -oE '"asOrganization":"[^"]+"' | grep -oE '":"[^"]+"' | sed 's/":"//g')
	    local ipv6_city=$(echo "$ipv6_output" | grep -oE '"city":"[^"]+"' | grep -oE '":"[^"]+"' | sed 's/":"//g')
	    local ipv6_region=$(echo "$ipv6_output" | grep -oE '"region":"[^"]+"' | grep -oE '":"[^"]+"' | sed 's/":"//g')
	    if [ -n "$ipv6_asn" ] && [ -n "$ipv6_as_organization" ] && [ -n "$ipv6_city" ] && [ -n "$ipv6_region" ]; then
	        local ipv6_asn_info="AS${ipv6_asn} ${ipv6_as_organization}"
	        local ipv6_location="${ipv6_city} / ${ipv6_region}"
	    else
	        local ipv6_asn_info="None"
	        local ipv6_location="None"
	    fi
	    # 去除双引号
	    if [[ $ipv6_asn_info == *"\""* ]]; then
	        ipv6_asn_info="${ipv6_asn_info//\"/}"
	    fi
	    if [[ $ipv6_location == *"\""* ]]; then
	        ipv6_location="${ipv6_location//\"/}"
	    fi
	    # 返回结果
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "IPV6 ASN" "${ipv6_asn_info}"
	printf "%-20s:\e[30;96m %-10s\n\e[0m" "IPV6 Location" "${ipv6_location}"
	} 
	check_ip_info_by_cloudflare
	;;
	2)
	  clear
	  update_system() {
	      if command -v apt &>/dev/null; then
	          apt-get update && apt-get upgrade -y
	      elif command -v dnf &>/dev/null; then
	          dnf check-update && dnf upgrade -y
	      elif command -v yum &>/dev/null; then
	          yum check-update && yum upgrade -y
	      elif command -v apk &>/dev/null; then
	          apk update && apk upgrade
	      else
	          echo -e "${red}不支持的Linux发行版${re}"
	          return 1
	      fi
	      return 0
	  }
	  update_system
	  ;;
	3)
	  clear
	      clean_system() {
	          if command -v apt &>/dev/null; then
	              apt autoremove --purge -y && apt clean -y && apt autoclean -y
	              apt remove --purge $(dpkg -l | awk '/^rc/ {print $2}') -y
	              # 清理包配置文件
	              journalctl --vacuum-time=1s
	              journalctl --vacuum-size=50M
	              # 移除不再需要的内核
	              apt remove --purge $(dpkg -l | awk '/^ii linux-(image|headers)-[^ ]+/{print $2}' | grep -v $(uname -r | sed 's/-.*//') | xargs) -y
	          elif command -v yum &>/dev/null; then
	              yum autoremove -y && yum clean all
	              # 清理日志
	              journalctl --vacuum-time=1s
	              journalctl --vacuum-size=50M
	              # 移除不再需要的内核
	              yum remove $(rpm -q kernel | grep -v $(uname -r)) -y
	          elif command -v dnf &>/dev/null; then
	              dnf autoremove -y && dnf clean all
	              # 清理日志
	              journalctl --vacuum-time=1s
	              journalctl --vacuum-size=50M
	              # 移除不再需要的内核
	              dnf remove $(rpm -q kernel | grep -v $(uname -r)) -y
	          elif command -v apk &>/dev/null; then
	              apk autoremove -y
	              apk clean
	              # 清理包配置文件
	              apk del $(apk info -e | grep '^r' | awk '{print $1}') -y
	              # 清理日志文件
	              journalctl --vacuum-time=1s
	              journalctl --vacuum-size=50M
	              # 移除不再需要的内核
	              apk del $(apk info -vv | grep -E 'linux-[0-9]' | grep -v $(uname -r) | awk '{print $1}') -y
	          else
	              echo -e "${red}暂不支持你的系统！${re}"
	              exit 1
	          fi
	      }
	      clean_system
	  ;;
	# 脚本更新
	  9)
	    cd ~
	    echo ""
	    curl -sS -O https://raw.githubusercontent.com/windtraceQ/bash_script/main/simple_info.sh -o simple_info.sh && chmod +x simple_info.sh
	    echo -e "${green}脚本已更新到最新版本！${re}"
	    break_end
	    main_menu
	    ;;
	  0)
	    clear
	    exit
	    ;;
	  *)
	    echo -e "${purple}无效的输入!${re}"
	    ;;
	esac
	    break_end
	done