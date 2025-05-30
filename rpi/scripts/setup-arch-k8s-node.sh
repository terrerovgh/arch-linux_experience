#!/bin/bash
# Script de configuración para nodo Arch Linux optimizado para Kubernetes
# Raspberry Pi 5 - Master Node
# Autor: Proyecto Surviving Chernarus
# Fecha: $(date +%Y-%m-%d)

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  🏴‍☠️ CHERNARUS SURVIVAL PROTOCOL - RASPBERRY PI 5 COMMAND CENTER 🏴‍☠️
# ═══════════════════════════════════════════════════════════════════════════════
#  Mission: Transform Raspberry Pi 5 into tactical K8s MASTER for Colectivo Chernarus
#  Target: Raspberry Pi 5 (ARM64) - Codename: "RPI"
#  Role: COMMAND CENTER - Master Node
#  Status: CLASSIFIED - Operator Terrerov Access Only
# ═══════════════════════════════════════════════════════════════════════════════

# Colores temáticos para output
RED='\033[0;31m'      # ⚠️  PELIGRO/ERROR
GREEN='\033[0;32m'    # ✅ MISIÓN COMPLETADA
YELLOW='\033[1;33m'   # ⚡ ADVERTENCIA/PROCESO
BLUE='\033[0;34m'     # 🔵 INFORMACIÓN
PURPLE='\033[0;35m'   # 🟣 SISTEMA
CYAN='\033[0;36m'     # 🔷 CONFIGURACIÓN
NC='\033[0m'          # Reset

# Configuración de red
STATIC_IP="192.168.0.2/25"
GATEWAY="192.168.0.1"
DNS_SERVER="1.1.1.1"
DOMAIN="terrerov.com"
HOSTNAME="rpi.terrerov.com"
USER_NAME="terrerov"
SSH_ALLOWED_NETWORK="192.168.0.0/25"

# Configuración específica de K3s Master
K3S_VERSION="v1.28.5+k3s1"
K3S_TOKEN="chernarus-survival-protocol-2024"
K3S_NODE_IP="192.168.0.2"
K3S_CLUSTER_CIDR="10.42.0.0/16"
K3S_SERVICE_CIDR="10.43.0.0/16"

# Funciones de output temáticas
print_status() {
    echo -e "${BLUE}🔍 [INTEL]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅ [MISIÓN COMPLETADA]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚡ [ALERTA TÁCTICA]${NC} $1"
}

print_error() {
    echo -e "${RED}💀 [CÓDIGO ROJO]${NC} $1"
}

print_mission() {
    echo -e "${PURPLE}🎯 [OBJETIVO]${NC} $1"
}

print_config() {
    echo -e "${CYAN}🔧 [CONFIGURANDO]${NC} $1"
}

print_banner() {
    echo -e "${GREEN}"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "  🏴‍☠️ CHERNARUS SURVIVAL PROTOCOL - COMMAND CENTER DEPLOYMENT 🏴‍☠️"
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

# Verificar que se ejecuta como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Acceso denegado. Se requieren privilegios de Operador (usa sudo)"
        exit 1
    fi
    print_success "Privilegios de Operador confirmados - Acceso autorizado"
}

# Verificar conectividad a internet
check_internet() {
    print_mission "Estableciendo enlace de comunicaciones..."
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        print_error "Fallo en comunicaciones. Verificar antena y repetidores."
        exit 1
    fi
    print_success "Enlace satelital establecido - Comunicaciones operativas"
}

# Actualizar sistema completo
update_system() {
    print_mission "Actualizando arsenal y equipamiento..."
    pacman -Syu --noconfirm
    print_success "Arsenal actualizado - Todas las armas listas para combate"
}

# Instalar paquetes esenciales
install_essential_packages() {
    print_status "Instalando paquetes esenciales para Raspberry Pi 5..."
    
    # Paquetes base del sistema
    local base_packages=(
        "base-devel"
        "linux-rpi"
        "linux-rpi-headers"
        "linux-firmware"
        "networkmanager"
        "openssh"
        "sudo"
        "vim"
        "nano"
        "htop"
        "curl"
        "wget"
        "git"
        "rsync"
        "unzip"
        "tar"
        "gzip"
    )
    
    # Paquetes específicos para Raspberry Pi
    local rpi_packages=(
        "raspberrypi-bootloader"
        "raspberrypi-firmware"
        "pi-bluetooth"
        "bluez"
        "bluez-utils"
    )
    
    # Herramientas de red y monitoreo
    local network_packages=(
        "iptables"
        "nftables"
        "bridge-utils"
        "net-tools"
        "bind-tools"
        "traceroute"
        "tcpdump"
        "nmap"
        "iperf3"
    )
    
    # Herramientas de sistema
    local system_packages=(
        "lsof"
        "strace"
        "sysstat"
        "iotop"
        "htop"
        "tree"
        "tmux"
        "screen"
    )
    
    # Herramientas para contenedores y Kubernetes
    local container_packages=(
        "docker"
        "containerd"
        "runc"
    )
    
    # Instalar todos los paquetes
    pacman -S --needed --noconfirm "${base_packages[@]}" "${rpi_packages[@]}" "${network_packages[@]}" "${system_packages[@]}" "${container_packages[@]}"
    
    print_success "Paquetes esenciales instalados"
}

# Limpiar paquetes innecesarios
clean_system() {
    print_status "Limpiando sistema de paquetes innecesarios..."
    
    # Remover paquetes huérfanos
    if pacman -Qtdq &> /dev/null; then
        pacman -Rns $(pacman -Qtdq) --noconfirm
        print_success "Paquetes huérfanos removidos"
    else
        print_status "No hay paquetes huérfanos para remover"
    fi
    
    # Limpiar cache de pacman
    pacman -Sc --noconfirm
    
    # Limpiar logs antiguos
    journalctl --vacuum-time=7d
    
    print_success "Sistema limpiado"
}

# Configurar usuario terrerov
setup_user() {
    print_status "Configurando usuario $USER_NAME..."
    
    # Crear usuario si no existe
    if ! id "$USER_NAME" &>/dev/null; then
        useradd -m -G wheel,docker -s /bin/bash "$USER_NAME"
        print_status "Usuario $USER_NAME creado"
        
        # Solicitar contraseña
        print_warning "Establece una contraseña para el usuario $USER_NAME:"
        passwd "$USER_NAME"
    else
        print_status "Usuario $USER_NAME ya existe"
        # Asegurar que esté en los grupos correctos
        usermod -aG wheel,docker "$USER_NAME"
    fi
    
    # Configurar sudo sin contraseña para wheel
    echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/wheel
    
    print_success "Usuario configurado"
}

# Configurar NetworkManager con IP estática
setup_network() {
    print_status "Configurando NetworkManager con IP estática..."
    
    # Habilitar y iniciar NetworkManager
    systemctl enable NetworkManager
    systemctl start NetworkManager
    
    # Obtener el nombre de la interfaz principal
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -z "$interface" ]]; then
        print_error "No se pudo detectar la interfaz de red principal"
        return 1
    fi
    
    print_status "Configurando interfaz: $interface"
    
    # Asegurarse de que el directorio existe
    mkdir -p "/etc/NetworkManager/system-connections"
    
    # Crear configuración de NetworkManager
    cat > "/etc/NetworkManager/system-connections/static-$interface.nmconnection" << EOF
[connection]
id=static-$interface
type=ethernet
interface-name=$interface
autoconnect=true

[ethernet]

[ipv4]
method=manual
addresses=$STATIC_IP
gateway=$GATEWAY
dns=$DNS_SERVER
dns-search=$DOMAIN

[ipv6]
method=ignore

[proxy]
EOF
    
    # Establecer permisos correctos
    chmod 600 "/etc/NetworkManager/system-connections/static-$interface.nmconnection"
    
    # Configurar hostname
    hostnamectl set-hostname "${HOSTNAME}"
    
    # Configurar /etc/hosts
    cat > /etc/hosts << EOF
127.0.0.1   localhost
::1         localhost
192.168.0.2 ${HOSTNAME} rpi
192.168.0.3 lenlab.terrerov.com lenlab
EOF
    
    print_success "Configuración de red completada"
}

# Configurar SSH seguro
setup_ssh() {
    print_status "Configurando SSH seguro..."
    
    # Backup de configuración original
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Crear nueva configuración SSH
    cat > /etc/ssh/sshd_config << EOF
# Configuración SSH para nodo Kubernetes Master
# Puerto SSH
Port 22

# Protocolo y cifrado
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Autenticación
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Usuarios permitidos
AllowUsers $USER_NAME

# Restricciones de red
ListenAddress 0.0.0.0

# Configuraciones de seguridad
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60

# Forwarding
AllowTcpForwarding yes
X11Forwarding no
AllowAgentForwarding yes

# Logging
SyslogFacility AUTH
LogLevel INFO

# Otros
UseDNS no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
EOF
    
    # Habilitar y iniciar SSH
    systemctl enable sshd
    systemctl start sshd
    
    print_success "SSH configurado y habilitado"
}

# Configurar firewall para Kubernetes Master
setup_firewall() {
    print_status "Configurando firewall para Kubernetes Master..."
    
    # Limpiar reglas existentes
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Permitir loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Permitir conexiones establecidas
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Permitir SSH desde red local
    iptables -A INPUT -p tcp --dport 22 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # Permitir ping desde red local
    iptables -A INPUT -p icmp --icmp-type echo-request -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # Puertos específicos para Kubernetes Master
    # API Server
    iptables -A INPUT -p tcp --dport 6443 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # etcd server client API
    iptables -A INPUT -p tcp --dport 2379:2380 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # Kubelet API
    iptables -A INPUT -p tcp --dport 10250 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # kube-scheduler
    iptables -A INPUT -p tcp --dport 10259 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # kube-controller-manager
    iptables -A INPUT -p tcp --dport 10257 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # K3s específicos
    iptables -A INPUT -p tcp --dport 10250 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    iptables -A INPUT -p tcp --dport 8472 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    iptables -A INPUT -p udp --dport 8472 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # Flannel VXLAN
    iptables -A INPUT -p udp --dport 8472 -j ACCEPT
    
    # Crear directorio si no existe
    mkdir -p /etc/iptables
    
    # Guardar reglas
    iptables-save > /etc/iptables/iptables.rules
    
    # Habilitar iptables
    systemctl enable iptables
    
    print_success "Firewall configurado para Master"
}

# Optimizaciones para Kubernetes
optimize_for_kubernetes() {
    print_status "Aplicando optimizaciones para Kubernetes Master..."
    
    # Asegurarse de que los directorios existen
    mkdir -p /etc/sysctl.d
    mkdir -p /etc/modules-load.d
    
    # Configurar parámetros del kernel
    cat > /etc/sysctl.d/99-kubernetes.conf << EOF
# Optimizaciones para Kubernetes Master

# Networking
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1

# Memory management
vm.swappiness = 1
vm.overcommit_memory = 1
vm.panic_on_oom = 0

# File system
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 1048576

# Network performance
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8096
net.core.netdev_max_backlog = 5000

# Kubernetes specific
net.netfilter.nf_conntrack_max = 1000000
net.core.netdev_budget = 600
EOF
    
    # Cargar módulos necesarios
    cat > /etc/modules-load.d/kubernetes.conf << EOF
br_netfilter
overlay
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack
EOF
    
    # Cargar módulos ahora
    modprobe br_netfilter
    modprobe overlay
    modprobe ip_vs
    modprobe ip_vs_rr
    modprobe ip_vs_wrr
    modprobe ip_vs_sh
    modprobe nf_conntrack
    
    # Aplicar configuración sysctl
    sysctl --system
    
    # Deshabilitar swap
    swapoff -a
    sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
    
    print_success "Optimizaciones aplicadas"
}

# Configurar servicios del sistema
setup_system_services() {
    print_status "Configurando servicios del sistema..."
    
    # Servicios a habilitar
    local services_enable=(
        "NetworkManager"
        "sshd"
        "systemd-timesyncd"
        "iptables"
        "docker"
        "containerd"
    )
    
    # Servicios a deshabilitar
    local services_disable=(
        "cups"
        "avahi-daemon"
    )
    
    # Habilitar servicios necesarios
    for service in "${services_enable[@]}"; do
        if systemctl list-unit-files | grep -qE "^${service}(\.service)?\s"; then
            systemctl enable "$service" 2>/dev/null || true
            print_status "Servicio $service habilitado"
        else
            print_warning "Servicio $service no encontrado, omitiendo..."
        fi
    done
    
    # Deshabilitar servicios innecesarios
    for service in "${services_disable[@]}"; do
        if systemctl list-unit-files | grep -qE "^${service}(\.service)?\s"; then
            systemctl disable "$service" 2>/dev/null || true
            systemctl stop "$service" 2>/dev/null || true
            print_status "Servicio $service deshabilitado"
        else
            print_status "Servicio $service no encontrado (ya deshabilitado)"
        fi
    done
    
    print_success "Servicios configurados"
}

# Configurar límites del sistema
setup_system_limits() {
    print_status "Configurando límites del sistema..."
    
    # Asegurarse de que el directorio existe antes de escribir el archivo
    mkdir -p /etc/security/limits.d
    
    cat > /etc/security/limits.d/99-kubernetes.conf << EOF
# Límites para Kubernetes Master
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
root soft nproc 32768
root hard nproc 32768
EOF
    
    # Configuración alternativa en caso de que limits.d no funcione
    if [ -f /etc/security/limits.conf ]; then
        # Hacer backup del archivo original
        cp /etc/security/limits.conf /etc/security/limits.conf.bak
        
        # Verificar si ya existen las configuraciones
        if ! grep -q "# Kubernetes limits" /etc/security/limits.conf; then
            print_status "Añadiendo límites a /etc/security/limits.conf..."
            cat >> /etc/security/limits.conf << EOF

# Kubernetes limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
root soft nproc 32768
root hard nproc 32768
EOF
        fi
    fi
    
    print_success "Límites del sistema configurados"
}

# Crear directorio de logs personalizado
setup_logging() {
    print_status "Configurando logging..."
    
    # Crear directorio para logs de Kubernetes
    mkdir -p /var/log/kubernetes
    chown $USER_NAME:$USER_NAME /var/log/kubernetes
    
    # Asegurarse de que el directorio de logrotate existe
    mkdir -p /etc/logrotate.d
    
    # Configurar logrotate para logs de Kubernetes
    cat > /etc/logrotate.d/kubernetes << EOF
/var/log/kubernetes/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    
    print_success "Logging configurado"
}

# Instalar K3s como Master
install_k3s_master() {
    print_mission "Instalando K3s como nodo Master..."
    
    # Crear directorio para configuración de K3s
    mkdir -p /etc/rancher/k3s
    
    # Crear archivo de configuración para K3s
    cat > /etc/rancher/k3s/config.yaml << EOF
# Configuración K3s Master - Chernarus Command Center
node-ip: $K3S_NODE_IP
cluster-cidr: $K3S_CLUSTER_CIDR
service-cidr: $K3S_SERVICE_CIDR
cluster-dns: 10.43.0.10
node-name: rpi-master
bind-address: $K3S_NODE_IP
advertise-address: $K3S_NODE_IP
tls-san:
  - $K3S_NODE_IP
  - rpi.terrerov.com
  - rpi
disable:
  - traefik
  - servicelb
write-kubeconfig-mode: 644
kubeconfig-update-interval: 5s
EOF
    
    # Descargar e instalar K3s
    curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s - server \
        --token="$K3S_TOKEN" \
        --config=/etc/rancher/k3s/config.yaml
    
    # Esperar a que K3s esté listo
    print_status "Esperando a que K3s esté operativo..."
    sleep 30
    
    # Verificar estado de K3s
    if systemctl is-active --quiet k3s; then
        print_success "K3s Master instalado y operativo"
    else
        print_error "Error al iniciar K3s Master"
        return 1
    fi
    
    # Configurar kubectl para el usuario
    mkdir -p /home/$USER_NAME/.kube
    cp /etc/rancher/k3s/k3s.yaml /home/$USER_NAME/.kube/config
    chown $USER_NAME:$USER_NAME /home/$USER_NAME/.kube/config
    chmod 600 /home/$USER_NAME/.kube/config
    
    # Crear alias para kubectl
    echo "alias k='kubectl'" >> /home/$USER_NAME/.bashrc
    echo "export KUBECONFIG=/home/$USER_NAME/.kube/config" >> /home/$USER_NAME/.bashrc
    
    print_success "Configuración de kubectl completada"
}

# Configurar herramientas adicionales de Kubernetes
setup_k8s_tools() {
    print_status "Configurando herramientas adicionales de Kubernetes..."
    
    # Instalar Helm
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    
    # Crear script de información del cluster
    cat > /home/$USER_NAME/cluster-info.sh << 'EOF'
#!/bin/bash
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  🏴‍☠️ CHERNARUS COMMAND CENTER - CLUSTER STATUS 🏴‍☠️"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo
echo "🎯 Master Node: $(hostname)"
echo "🌐 Node IP: $(hostname -I | awk '{print $1}')"
echo "📊 K3s Status: $(systemctl is-active k3s)"
echo
echo "📋 Cluster Nodes:"
kubectl get nodes -o wide
echo
echo "🔧 System Resources:"
echo "CPU: $(nproc) cores"
echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $4" available"}')"
echo
echo "🔑 Join Token for Workers:"
echo "sudo k3s agent --server https://192.168.0.2:6443 --token $(cat /var/lib/rancher/k3s/server/node-token)"
echo "═══════════════════════════════════════════════════════════════════════════════"
EOF
    
    chmod +x /home/$USER_NAME/cluster-info.sh
    chown $USER_NAME:$USER_NAME /home/$USER_NAME/cluster-info.sh
    
    print_success "Herramientas adicionales configuradas"
}

# Función principal
main() {
    print_banner
    
    echo -e "${PURPLE}📋 BRIEFING DE MISIÓN:${NC}"
    echo -e "${BLUE}Transformar Raspberry Pi 5 en Centro de Comando K8s Master${NC}"
    echo -e "${BLUE}Codename: RPI - Sector: ${DOMAIN}${NC}"
    echo
    echo -e "${CYAN}🎯 OBJETIVOS TÁCTICOS:${NC}"
    echo -e "   🌐 Establecer comunicaciones de comando:"
    echo -e "      • IP de comando: ${STATIC_IP}"
    echo -e "      • Base de operaciones: ${GATEWAY}"
    echo -e "      • Servidor DNS: ${DNS_SERVER}"
    echo -e "      • Identidad: ${HOSTNAME}"
    echo
    echo -e "   👤 Registrar Comandante autorizado:"
    echo -e "      • Comandante: ${USER_NAME}"
    echo -e "      • Acceso SSH restringido: 192.168.0.0/25"
    echo
    echo -e "   🔧 Configuración de Centro de Comando:"
    echo -e "      • Raspberry Pi 5 ARM64 optimizado"
    echo -e "      • K3s Master Node para cluster táctico"
    echo -e "      • Perímetro de seguridad avanzado"
    echo -e "      • Token de cluster: ${K3S_TOKEN}"
    echo -e "      • CIDR del cluster: ${K3S_CLUSTER_CIDR}"
    echo
    echo -e "${RED}⚠️  ALERTA: Esta operación transformará el sistema en Centro de Comando${NC}"
    echo -e "${YELLOW}🔒 Solo personal autorizado debe proceder${NC}"
    echo
    read -p "🎯 ¿Autorizar inicio de operación de Centro de Comando? (y/N): " -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_error "Operación abortada - Regresando a base"
        exit 0
    fi
    
    print_success "Operación autorizada - Iniciando protocolo de Centro de Comando"
    
    check_root
    check_internet
    update_system
    install_essential_packages
    clean_system
    setup_user
    setup_network
    setup_ssh
    setup_firewall
    optimize_for_kubernetes
    setup_system_services
    setup_system_limits
    setup_logging
    install_k3s_master
    setup_k8s_tools
    
    print_banner
    echo -e "${GREEN}🎯 MISIÓN COMPLETADA - CENTRO DE COMANDO OPERATIVO${NC}"
    echo
    echo -e "${CYAN}📊 ESTADO DEL SISTEMA:${NC}"
    echo -e "   🖥️  Hostname: $(hostname)"
    echo -e "   🌐 IP Address: $(hostname -I | awk '{print $1}')"
    echo -e "   👤 Usuario: $USER_NAME (configurado)"
    echo -e "   🔒 SSH: Habilitado (puerto 22)"
    echo -e "   🛡️  Firewall: Configurado para K8s Master"
    echo -e "   ⚙️  K3s Master: $(systemctl is-active k3s)"
    echo
    echo -e "${PURPLE}🔑 INFORMACIÓN DE CONEXIÓN PARA WORKERS:${NC}"
    echo -e "   Token: $K3S_TOKEN"
    echo -e "   Server: https://192.168.0.2:6443"
    echo
    echo -e "${YELLOW}📋 COMANDOS ÚTILES:${NC}"
    echo -e "   • Ver estado del cluster: ./cluster-info.sh"
    echo -e "   • Ver nodos: kubectl get nodes"
    echo -e "   • Ver pods: kubectl get pods -A"
    echo -e "   • Token para workers: cat /var/lib/rancher/k3s/server/node-token"
    echo
    echo -e "${GREEN}🏴‍☠️ CENTRO DE COMANDO CHERNARUS LISTO PARA OPERACIONES 🏴‍☠️${NC}"
    echo -e "${BLUE}Reinicia el sistema para aplicar todos los cambios: sudo reboot${NC}"
}

# Ejecutar función principal
main "$@"