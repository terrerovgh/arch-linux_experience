#!/bin/bash
# Script de configuración para nodo Arch Linux optimizado para Kubernetes
# Lenovo IdeaPad 320 AMD A12 7th Gen
# Autor: Proyecto Surviving Chernarus
# Fecha: $(date +%Y-%m-%d)

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
#  🏴‍☠️ CHERNARUS SURVIVAL PROTOCOL - LENOVO IDEAPAD 320 FIELD PREPARATION 🏴‍☠️
# ═══════════════════════════════════════════════════════════════════════════════
#  Mission: Transform civilian laptop into tactical K8s node for Colectivo Chernarus
#  Target: Lenovo IdeaPad 320 (AMD A12) - Codename: "LENLAB"
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
STATIC_IP="192.168.0.3/25"
GATEWAY="192.168.0.1"
DNS_SERVER="1.1.1.1"
DOMAIN="terrerov.com"
HOSTNAME="lenlab.terrerov.com"
USER_NAME="terrerov"
SSH_ALLOWED_NETWORK="192.168.0.0/25"

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
    echo "  🏴‍☠️ CHERNARUS SURVIVAL PROTOCOL - TACTICAL NODE DEPLOYMENT 🏴‍☠️"
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
    print_status "Instalando paquetes esenciales..."
    
    # Paquetes base del sistema
    local base_packages=(
        "base-devel"
        "linux-headers"
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
    
    # Drivers y soporte de hardware AMD
    local amd_packages=(
        "mesa"
        "xf86-video-amdgpu"
        "vulkan-radeon"
        "libva-mesa-driver"
        "mesa-vdpau"
        "amd-ucode"
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
        "dstat"
        "tree"
        "tmux"
        "screen"
    )
    
    # Instalar todos los paquetes
    pacman -S --needed --noconfirm "${base_packages[@]}" "${amd_packages[@]}" "${network_packages[@]}" "${system_packages[@]}"
    
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
        useradd -m -G wheel -s /bin/bash "$USER_NAME"
        print_status "Usuario $USER_NAME creado"
        
        # Solicitar contraseña
        print_warning "Establece una contraseña para el usuario $USER_NAME:"
        passwd "$USER_NAME"
    else
        print_status "Usuario $USER_NAME ya existe"
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
192.168.0.3 ${HOSTNAME} lenlab
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
# Configuración SSH para nodo Kubernetes
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

# Configurar firewall básico
setup_firewall() {
    print_status "Configurando firewall básico..."
    
    # Instalar y configurar iptables básico
    # Permitir SSH solo desde la red local
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Permitir loopback
    iptables -A INPUT -i lo -j ACCEPT
    
    # Permitir conexiones establecidas
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Permitir SSH desde red local
    iptables -A INPUT -p tcp --dport 22 -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # Permitir ping desde red local
    iptables -A INPUT -p icmp --icmp-type echo-request -s $SSH_ALLOWED_NETWORK -j ACCEPT
    
    # Guardar reglas
    iptables-save > /etc/iptables/iptables.rules
    
    # Habilitar iptables
    systemctl enable iptables
    
    print_success "Firewall configurado"
}

# Optimizaciones para Kubernetes
optimize_for_kubernetes() {
    print_status "Aplicando optimizaciones para Kubernetes..."
    
    # Configurar parámetros del kernel
    cat > /etc/sysctl.d/99-kubernetes.conf << EOF
# Optimizaciones para Kubernetes

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
EOF
    
    # Cargar módulos necesarios
    cat > /etc/modules-load.d/kubernetes.conf << EOF
br_netfilter
overlay
EOF
    
    # Cargar módulos ahora
    modprobe br_netfilter
    modprobe overlay
    
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
    )
    
    # Servicios a deshabilitar
    local services_disable=(
        "bluetooth"
        "cups"
        "avahi-daemon"
    )
    
    # Habilitar servicios necesarios
    for service in "${services_enable[@]}"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            systemctl enable "$service"
            print_status "Servicio $service habilitado"
        fi
    done
    
    # Deshabilitar servicios innecesarios
    for service in "${services_disable[@]}"; do
        if systemctl list-unit-files | grep -q "^$service"; then
            systemctl disable "$service" 2>/dev/null || true
            systemctl stop "$service" 2>/dev/null || true
            print_status "Servicio $service deshabilitado"
        fi
    done
    
    print_success "Servicios configurados"
}

# Configurar límites del sistema
setup_system_limits() {
    print_status "Configurando límites del sistema..."
    
    cat > /etc/security/limits.d/99-kubernetes.conf << EOF
# Límites para Kubernetes
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
root soft nproc 32768
root hard nproc 32768
EOF
    
    print_success "Límites del sistema configurados"
}

# Crear directorio de logs personalizado
setup_logging() {
    print_status "Configurando logging..."
    
    # Crear directorio para logs de Kubernetes
    mkdir -p /var/log/kubernetes
    chown $USER_NAME:$USER_NAME /var/log/kubernetes
    
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

# Función principal
main() {
    print_banner
    
    echo -e "${PURPLE}📋 BRIEFING DE MISIÓN:${NC}"
    echo -e "${BLUE}Transformar laptop civil Lenovo IdeaPad 320 en nodo táctico K8s${NC}"
    echo -e "${BLUE}Codename: LENLAB - Sector: ${DOMAIN}${NC}"
    echo
    echo -e "${CYAN}🎯 OBJETIVOS TÁCTICOS:${NC}"
    echo -e "   🌐 Establecer comunicaciones seguras:"
    echo -e "      • IP de combate: ${STATIC_IP}"
    echo -e "      • Base de operaciones: ${GATEWAY}"
    echo -e "      • Servidor DNS: ${DNS_SERVER}"
    echo -e "      • Identidad: ${HOSTNAME}"
    echo
    echo -e "   👤 Registrar Operador autorizado:"
    echo -e "      • Operador: ${USER_NAME}"
    echo -e "      • Acceso SSH restringido: 192.168.0.0/25"
    echo
    echo -e "   🔧 Optimizaciones de combate:"
    echo -e "      • Drivers AMD A12 para máximo rendimiento"
    echo -e "      • Configuración Kubernetes para cluster táctico"
    echo -e "      • Perímetro de seguridad (firewall)"
    echo -e "      • Eliminación de software civil innecesario"
    echo
    echo -e "${RED}⚠️  ALERTA: Esta operación modificará permanentemente el sistema${NC}"
    echo -e "${YELLOW}🔒 Solo personal autorizado debe proceder${NC}"
    echo
    read -p "🎯 ¿Autorizar inicio de operación? (y/N): " -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_error "Operación abortada - Regresando a base"
        exit 0
    fi
    
    print_success "Operación autorizada - Iniciando protocolo de supervivencia"
    
    check_root
    check_internet
    
    # Ejecutar configuraciones
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
    
    echo
    print_success "\n═══════════════════════════════════════════════════════════════════════════════"
    print_success "  🏴‍☠️ MISIÓN COMPLETADA - NODO TÁCTICO OPERATIVO 🏴‍☠️"
    print_success "═══════════════════════════════════════════════════════════════════════════════"
    echo
    echo -e "${GREEN}📋 REPORTE DE ESTADO FINAL:${NC}"
    echo -e "   🌐 Comunicaciones: ${STATIC_IP} - OPERATIVO"
    echo -e "   🏠 Identidad táctica: ${HOSTNAME} - CONFIRMADA"
    echo -e "   🌍 Sector de operaciones: ${DOMAIN} - ASEGURADO"
    echo -e "   👤 Operador registrado: ${USER_NAME} - AUTORIZADO"
    echo -e "   🔒 Perímetro SSH: 192.168.0.0/25 - FORTIFICADO"
    echo -e "   🔧 Arsenal K8s: CARGADO Y LISTO"
    echo
    echo -e "${CYAN}🎯 PROTOCOLO DE ACTIVACIÓN:${NC}"
    echo -e "   1. 🔄 Reiniciar nodo: sudo reboot"
    echo -e "   2. 📡 Verificar comunicaciones de red"
    echo -e "   3. 🔐 Probar acceso SSH desde base de operaciones"
    echo -e "   4. ⚔️  Nodo listo para unirse al Colectivo Chernarus"
    echo
    print_warning "🔑 CRÍTICO: Configurar contraseña del Operador ${USER_NAME} post-reinicio"
    echo -e "${PURPLE}🏴‍☠️ Bienvenido al Colectivo Chernarus, Operador. La supervivencia comienza ahora.${NC}"
    echo
}

# Ejecutar función principal
main "$@"