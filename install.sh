#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
    x86_64 | x64 | amd64) echo 'amd64' ;;
    i*86 | x86) echo '386' ;;
    armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
    armv7* | armv7 | arm) echo 'armv7' ;;
    armv6* | armv6) echo 'armv6' ;;
    armv5* | armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "arch: $(arch)"

install_dependencies() {
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update && apt-get install -y -q wget curl tar tzdata cron
        ;;
    centos | almalinux | rocky | ol)
        yum -y update && yum install -y -q wget curl tar tzdata cronie
        ;;
    fedora | amzn)
        dnf -y update && dnf install -y -q wget curl tar tzdata cronie
        ;;
    arch | manjaro | parch)
        pacman -Syu && pacman -Syu --noconfirm wget curl tar tzdata cronie
        ;;
    opensuse-tumbleweed)
        zypper refresh && zypper -q install -y wget curl tar timezone cron
        ;;
    *)
        apt-get update && apt install -y -q wget curl tar tzdata cron
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

config_after_install() {
    local existing_username=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'username: .+' | awk '{print $2}')
    local existing_password=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'password: .+' | awk '{print $2}')
    local existing_webBasePath=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')

    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
            local config_webBasePath=$(gen_random_string 15)
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)

            read -p "Would you like to customize the Panel Port settings? (If not, random port will be applied) [y/n]: " config_confirm
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                read -p "Please set up the panel port: " config_port
                echo -e "${yellow}Your Panel Port is: ${config_port}${plain}"
            else
                local config_port=$(shuf -i 1024-62000 -n 1)
                echo -e "${yellow}Generated random port: ${config_port}${plain}"
            fi

            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
            echo -e "This is a fresh installation, generating random login info for security concerns:"
            echo -e "###############################################"
            echo -e "${green}Username: ${config_username}${plain}"
            echo -e "${green}Password: ${config_password}${plain}"
            echo -e "${green}Port: ${config_port}${plain}"
            echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
            echo -e "###############################################"
            echo -e "${yellow}If you forgot your login info, you can type 'x-ui settings' to check${plain}"
        else
            local config_webBasePath=$(gen_random_string 15)
            echo -e "${yellow}WebBasePath is missing or too short. Generating a new one...${plain}"
            /usr/local/x-ui/x-ui setting -webBasePath "${config_webBasePath}"
            echo -e "${green}New WebBasePath: ${config_webBasePath}${plain}"
        fi
    else
        if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)

            echo -e "${yellow}Default credentials detected. Security update required...${plain}"
            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}"
            echo -e "Generated new random login credentials:"
            echo -e "###############################################"
            echo -e "${green}Username: ${config_username}${plain}"
            echo -e "${green}Password: ${config_password}${plain}"
            echo -e "###############################################"
            echo -e "${yellow}If you forgot your login info, you can type 'x-ui settings' to check${plain}"
        else
            echo -e "${green}Username, Password, and WebBasePath are properly set. Exiting...${plain}"
        fi
    fi

    /usr/local/x-ui/x-ui migrate
}

install_x-ui() {
    # checks if the installation backup dir exist. if existed then ask user if they want to restore it else continue installation.
    if [[ -e /usr/local/x-ui-backup/ ]]; then
        read -p "Failed installation detected. Do you want to restore previously installed version? [y/n]? ": restore_confirm
        if [[ "${restore_confirm}" == "y" || "${restore_confirm}" == "Y" ]]; then
            systemctl stop x-ui
            mv /usr/local/x-ui-backup/x-ui.db /etc/x-ui/ -f
            mv /usr/local/x-ui-backup/ /usr/local/x-ui/ -f
            systemctl start x-ui
            echo -e "${green}previous installed x-ui restored successfully${plain}, it is up and running now..."
            exit 0
        else
            echo -e "Continuing installing x-ui ..."
        fi
    fi

    # Install git and unzip if not present
    echo -e "${green}Installing prerequisites (git, unzip)...${plain}"
    if [[ "${release}" == "ubuntu" || "${release}" == "debian" || "${release}" == "armbian" ]]; then
        apt-get install -y -q git unzip
    elif [[ "${release}" == "centos" || "${release}" == "almalinux" || "${release}" == "rocky" || "${release}" == "ol" ]]; then
        yum install -y -q git unzip
    elif [[ "${release}" == "fedora" || "${release}" == "amzn" ]]; then
        dnf install -y -q git unzip
    elif [[ "${release}" == "arch" || "${release}" == "manjaro" || "${release}" == "parch" ]]; then
        pacman -Syu --noconfirm git unzip
    fi

    # Install Go temporarily if not present
    if ! command -v go &> /dev/null; then
        echo -e "${yellow}Go is not installed. Temporarily downloading Go to compile x-ui from source...${plain}"
        local go_version="1.21.8"
        local go_arch="amd64"
        case "$(uname -m)" in
            x86_64 | x64 | amd64) go_arch="amd64" ;;
            armv8* | armv8 | arm64 | aarch64) go_arch="arm64" ;;
            i*86 | x86) go_arch="386" ;;
            armv7* | armv7 | arm) go_arch="armv7l" ;;
            *) echo -e "${red}Unsupported CPU architecture for Go compilation!${plain}" && exit 1 ;;
        esac
        wget -qN --no-check-certificate -O /tmp/go.tar.gz "https://go.dev/dl/go${go_version}.linux-${go_arch}.tar.gz"
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Failed to download Go compiler!${plain}"
            exit 1
        fi
        rm -rf /tmp/go
        tar -C /tmp -xzf /tmp/go.tar.gz
        export PATH=$PATH:/tmp/go/bin
        rm -f /tmp/go.tar.gz
    fi

    # Clone source code
    echo -e "${green}Cloning x-ui source code from your repository...${plain}"
    rm -rf /tmp/x-ui-source
    git clone https://github.com/akbartelbank-ux/x-ui.git /tmp/x-ui-source
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Cloning repository failed!${plain}"
        exit 1
    fi

    cd /tmp/x-ui-source
    echo -e "${green}Compiling x-ui from source...${plain}"
    go build -v -o /tmp/x-ui-source/x-ui main.go
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Compilation failed!${plain}"
        exit 1
    fi

    # Download Xray-core
    echo -e "${green}Downloading official Xray-core binary...${plain}"
    local xray_version="v26.2.6"
    local xray_arch="linux-64"
    case "$(uname -m)" in
        x86_64 | x64 | amd64) xray_arch="linux-64" ;;
        armv8* | armv8 | arm64 | aarch64) xray_arch="linux-arm64-v8a" ;;
        i*86 | x86) xray_arch="linux-32" ;;
        armv7* | armv7 | arm) xray_arch="linux-arm32-v7a" ;;
        *) echo -e "${red}Unsupported CPU architecture for Xray-core!${plain}" && exit 1 ;;
    esac
    mkdir -p /tmp/x-ui-source/bin
    wget -qN --no-check-certificate -O /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${xray_version}/Xray-${xray_arch}.zip"
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to download Xray-core!${plain}"
        exit 1
    fi
    mkdir -p /tmp/xray_temp
    unzip -q -o /tmp/xray.zip -d /tmp/xray_temp
    mv /tmp/xray_temp/xray /tmp/x-ui-source/bin/xray-linux-$(arch)
    mv /tmp/xray_temp/geoip.dat /tmp/x-ui-source/bin/geoip.dat
    mv /tmp/xray_temp/geosite.dat /tmp/x-ui-source/bin/geosite.dat
    rm -rf /tmp/xray.zip /tmp/xray_temp

    # Clean up temporary Go if we installed it
    if [[ -d /tmp/go ]]; then
        rm -rf /tmp/go
    fi

    # Move to destination
    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui
        mv /usr/local/x-ui/ /usr/local/x-ui-backup/ -f
        cp /etc/x-ui/x-ui.db /usr/local/x-ui-backup/ -f
    fi

    mkdir -p /usr/local/x-ui
    cp -rf /tmp/x-ui-source/* /usr/local/x-ui/
    rm -rf /tmp/x-ui-source

    cd /usr/local/x-ui
    chmod +x x-ui

    if [[ $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)
    cp -f x-ui.service /etc/systemd/system/
    wget --no-check-certificate -O /usr/bin/x-ui https://raw.githubusercontent.com/akbartelbank-ux/x-ui/main/x-ui.sh
    chmod +x /usr/local/x-ui/x-ui.sh
    chmod +x /usr/bin/x-ui

    config_after_install
    rm /usr/local/x-ui-backup/ -rf

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl restart x-ui
    echo -e "${green}x-ui compiled and installed successfully from source!${plain}"
    echo -e ""
    /usr/local/x-ui/x-ui uri
    echo -e "${plain}"
    echo "X-UI Control Menu Usage"
    echo "------------------------------------------"
    echo "SUBCOMMANDS:"
    echo "x-ui              - Admin Management Script"
    echo "x-ui start        - Start"
    echo "x-ui stop         - Stop"
    echo "x-ui restart      - Restart"
    echo "x-ui status       - Current Status"
    echo "x-ui settings     - Current Settings"
    echo "x-ui enable       - Enable Autostart on OS Startup"
    echo "x-ui disable      - Disable Autostart on OS Startup"
    echo "x-ui log          - Check Logs"
    echo "x-ui update       - Update"
    echo "x-ui install      - Install"
    echo "x-ui uninstall    - Uninstall"
    echo "x-ui help         - Control Menu Usage"
    echo "------------------------------------------"
}

echo -e "${green}Running...${plain}"
install_dependencies
install_x-ui $1
