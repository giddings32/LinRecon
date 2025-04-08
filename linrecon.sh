#!/bin/bash

# Font Color Codes
BLACK="\e[30m"
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
WHITEBG="\e[47m"
RESET="\e[0m"

# Define default state for functions
EnableSystemInfo=true
EnableUsers=true
EnableNetworks=true
EnableRunningProcesses=true
EnableFirewallRules=true
EnableCronJobs=true
EnableFilePermissions=true
EnableDrives=true
EnableKernelModules=true
EnableCVE=true

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $(echo "$1" | tr '[:upper:]' '[:lower:]') in
        --full|-f)
            EnableSystemInfo=true
            EnableUsers=true
            EnableNetworks=true
            EnableRunningProcesses=true
            EnableFirewallRules=true
            EnableCronJobs=true
            EnableFilePermissions=true
            EnableDrives=true
            EnableKernelModules=true
            EnableCVE=true
            shift
            ;;
        --exclude|-x)
            IFS=',' read -ra EXCLUDE <<< "$2"
            for func in "${EXCLUDE[@]}"; do
                case $(echo "$func" | tr '[:upper:]' '[:lower:]') in
                    "1"|"systeminfo"|"sysinfo") EnableSystemInfo=false ;;
                    "2"|"users"|"usr") EnableUsers=false ;;
                    "3"|"networks"|"net") EnableNetworks=false ;;
                    "4"|"runningprocesses"|"proc") EnableRunningProcesses=false ;;
                    "5"|"firewallrules"|"fw") EnableFirewallRules=false ;;
                    "6"|"cronjobs"|"cron") EnableCronJobs=false ;;
                    "7"|"filepermissions"|"fsp") EnableFilePermissions=false ;;
                    "8"|"drives"|"drv") EnableDrives=false ;;
                    "9"|"kernelmodules"|"km") EnableKernelModules=false ;;
                    "10"|"cve") EnableCVE=false ;;
                    *) echo "Invalid function name: $func" ;;
                esac
            done
            shift 2
            ;;
        --include|-i)
            EnableSystemInfo=false
            EnableUsers=false
            EnableNetworks=false
            EnableRunningProcesses=false
            EnableFirewallRules=false
            EnableCronJobs=false
            EnableFilePermissions=false
            EnableDrives=false
            EnableKernelModules=false
            EnableCVE=false
            IFS=',' read -ra INCLUDE <<< "$2"
            for func in "${INCLUDE[@]}"; do
                case $(echo "$func" | tr '[:upper:]' '[:lower:]') in
                    "1"|"systeminfo"|"sysinfo") EnableSystemInfo=true ;;
                    "2"|"users"|"usr") EnableUsers=true ;;
                    "3"|"networks"|"net") EnableNetworks=true ;;
                    "4"|"runningprocesses"|"proc") EnableRunningProcesses=true ;;
                    "5"|"firewallrules"|"fw") EnableFirewallRules=true ;;
                    "6"|"cronjobs"|"cron") EnableCronJobs=true ;;
                    "7"|"filepermissions"|"fp") EnableFilePermissions=true ;;
                    "8"|"drives"|"drv") EnableDrives=true ;;
                    "9"|"kernelmodules"|"km") EnableKernelModules=true ;;
                    "19"|"cve") EnableCVE=true ;;
                    *) echo "Invalid function name: $func" ;;
                esac
            done
            shift 2
            ;;
        --sudo|-s)
            sudo -v
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --full, -f          Run full recon (enable all functions)"
            echo "  --exclude, -x LIST  Exclude specific functions (comma-separated)"
            echo "  --include, -i LIST  Include only specific functions (comma-separated)"
            echo "  --sudo, -s          Run with sudo credentials"
            echo "  --help, -h          Show this help message"
            echo
            echo "Available Functions for Include/Exclude:"
            echo "  SystemInfo (sysinfo)          Collect system information"
            echo "  Users (usr)                   Gather user details"
            echo "  Networks (net)                Check network configuration"
            echo "  RunningProcesses (proc)       List running processes"
            echo "  FirewallRules (fw)            Review firewall rules"
            echo "  CronJobs (cron)               Inspect cron jobs"
            echo "  FilePermissions (fp)   Check filesystem permissions"
            echo "  Drives (drv)                  List drive details"
            echo "  KernelModules (km)            Review kernel modules"
            echo "  CVE (cve)            Check CVEs"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

user=$(whoami)
userid=$(cat /etc/passwd | grep "${user}" | cut -d : -f 3)

SystemInfo () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                    System Info                    ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"

    hostname=$(hostname)
    os_release=$(cat /etc/os-release | grep 'PRETTY_NAME' | cut -d '"' -f 2)
    os_short=$(cat /etc/os-release | grep 'PRETTY_NAME' |cut -d '"' -f 2 | cut -d '.' -f 1)
    arch=$(arch)
    version=$(uname -r)
    version_short=$(uname -a | awk '{print $3}' | cut -d '-' -f 1)

    printf "\n${CYAN}Hostname:${RESET} $hostname\n"
    printf "${CYAN}OS:${RESET} $os_release $version $arch\n"
    printf "${CYAN}searchsploit${RESET} \"Linux Kernel $os_short Local Privilege Escalation\" | grep -v \" < $version_short\"\n"
}

Users () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                      Users                        ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"

    printf "\n${CYAN}[+] Current User - whoami${RESET}\n"
    echo $user

    printf "\n${CYAN}[+] All Users - cat /etc/passwd${RESET}\n"
    cat /etc/passwd | grep -E ".*:.*:(1[0-9]{3}|0):.*" | cut -d : -f 1
    
}

Networks () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                     Networks                      ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    
    printf "\n${CYAN}[+] ip a ${RESET}- https://github.com/giddings32/Pentesting_Notes/blob/main/Linux/PortForwardingNotes.md\n"
    ipa=$(ip a | grep -E '^[0-9]{1,3}:|inet' | sed 's/^\s*//g' | awk '{print $2}' | sed ':a;N;$!ba;s/:\n/ - /g' | sed -e '/::/d' | grep -v "127.0.0.1")

    if [[ `echo "$ipa" | wc -l` -ge 2 ]]; then
        printf "${YELLOW}$ipa${RESET}\n"
    else
        printf "$ipa\n"
    fi

    route_check=$(route 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        printf "\n${CYAN}[+] route ${RESET}\n"
        printf "$route_check\n"
    else
        printf "\n${CYAN}[+] routel ${RESET}\n"
	routel 2>/dev/null | awk '{ printf "%-10s %-20s %-20s\n", $6, $3, $1 }' | grep -Ev '^(host| )'
    fi
    
    ss_check=$(ss -anp 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        printf "\n${CYAN}[+] ss -anp ${RESET}\n"
	ss -anp 2>/dev/null | sed 's/  */ /g' | grep "Netid" |  awk '{printf "%-10s %-15s %-25s %-0s\n", $1, $2, $5, $7 }'
	ss -anp 2>/dev/null | sed 's/  */ /g' | grep -E "^(udp|tcp)" | sort -u | awk '{printf "%-10s %-15s %-25s %-0s\n", $1, $2, $5, $6 }'

    else
        printf "\n${CYAN}[+] netstat -anp${RESET}\n"
        netstat -anp 2>/dev/null | sed 's/  */ /g' | grep -E "^(Proto Recv-Q)" | awk '{printf "%-10s %-15s %-25s %-25s %-0s\n", $1, $8, $4, $6, $9 }'
        netstat -anp 2>/dev/null | sed 's/  */ /g' | grep -E "^(udp|tcp)" | sort -u | awk '{printf "%-10s %-15s %-25s %-25s %-0s\n", $1, $6, $4, $5, $7 }'
    fi
}

RunningProcesses () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                 Running Processes                 ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    # Define local color variables that correctly interpret escape sequences
    local red=$'\033[31m'
    local reset=$'\033[0m'
    
    pswhitelist=(
        "^USER COMMAND\s*$"
        "^root\s*\/sbin\/init\s*$"
        "^root\s*\[irq/[0-9]{1,3}-vmwgfx\]\s*$"
        "^root\s*\[irq/[0-9]{1,3}-pciehp\]\s*$"
        "^root\s*\[migration\/[0-9]{1,3}\]\s*$"
        "^root\s*\[[^ ]*\]\s*$"
        "^root\s*\/usr\/sbin\/cron\s*\-f\s*$"
        "^root\s*\/lib\/systemd\/systemd\-[^ ]*\s$"
        "^root\s*\/usr\/bin\/vmtoolsd\s*$"
        "^root\s*\/usr\/bin\/VGAuthService\s*$"
        "^root\s*\/usr\/sbin\/rsyslogd\s*\-n \-iNONE\s*$"
        "^root\s*gdm\-session\-worker\s*\[pam\/gdm\-launch\-environment\]\s*$"
        "^root\s*\/usr\/sbin\/cups\-browsed\s*$"
        "^root\s*\/usr\/sbin\/cupsd\s*\-l\s*$"
        "^root\s*\/usr\/sbin\/gdm3\s*$"
        "^root\s*\/usr\/sbin\/ModemManager\s*\-\-filter\-policy\=strict\s*$"
        "^root\s*\/usr\/lib\/accountsservice\/accounts\-daemon\s*$"
        "^root\s*\/usr\/lib\/upower\/upowerd\s*$"
        "^root\s*\/usr\/libexec\/upowerd\s*$"
        "^root\s*\/usr\/(lib|libexec)\/udisks2\/udisksd\s*$"
        "^root\s*\/usr\/lib\/policykit\-1\/polkitd\s*\-\-no\-debug\s*$"
        "^root\s*\/sbin\/wpa\_supplicant\s*\-u\s*\-s\s*\-O\s*\/run\/wpa\_supplicant\s*$"
        "^root\s*\/usr\/lib\/systemd\/systemd\-[^ ]*\s*$"
        "^Debian\-\+\s*\/.*$"
        "^rtkit\s*\/usr\/lib\/rtkit\/rtkit\-daemon\s*$" 
        "^systemd\+\s*\/lib\/systemd\/systemd\-[^ ]*\s$"
        "^colord\s*\/usr\/lib\/colord\/colord\s*$"
        "^message\+\s*\/usr\/bin\/dbus\-daemon.*$"
        "^avahi\s*avahi\-daemon\:.*$"
        "^[^\s ]*\s*\(sd\-pam\)\s*$"
        "^[a-z]*\s*\/lib\/systemd\/systemd\s*\-\-user\s*$"
        "^$user\s*\[bash\]\s*$"
        "^$user\s*ps\s*\-aux\s*$"
        "^$user\s*-bash\s*$"
        "^$user\s*bash\s*$"
        "^$user\s*sed s\/\s*\*\/\s*\/g\s*$"
        "^$user\s*\/usr\/bin\/dbus\-daemon.*$"
        "^$user\s*sort\s*\-u\s*$"
        "^$user\s*\/usr\/libexec\/gvfs[^ ]*\s*$"
        "^$user\s*\/usr\/lib\/x86\_64\-linux\-gnu\/xfce4\/.*$"
        "^$user\s*grep\s*\-vE \^USER\s*COMMAND\\\s.*$"
        "^$user\s*awk\s*\{print\s*\\\$1\s*\"\s*\"\s*\\\$11,\s*substr.*$"
    )
    
    pswhitelist_pattern=$(IFS='|'; echo "${pswhitelist[*]}")
    printf "\n${CYAN}[+] ps -aux ${RESET}\n"
    ps -aux | awk '{print $1 " " $11, substr($0, index($0, $11) + length($11))}' | sed 's/  */ /g' | grep -vE "$pswhitelist_pattern" | sort -u | sed '/-[pP]/ s/^/'"$red"'/; /-[pP]/ s/$/'"$reset"'/'
    
    local pspy_bin="./pspy64"
    printf "\n${CYAN}[+] pspy ${RESET}\n"
    if [ ! -x "$pspy_bin" ]; then
        echo -e "${YELLOW}pspy64 binary not found. Please download it from https://github.com/DominicBreuker/pspy and place it in the same directory.${RESET}"
        return 1
    fi
    echo -e "${CYAN}Starting process monitoring using pspy64 for 1 minute in the background...${RESET}"
    local tmpfile=$(mktemp)
    timeout 1m "$pspy_bin" > "$tmpfile" 2>&1
    echo -e "${CYAN}Processing pspy64 output...${RESET}"
    grep '|' "$tmpfile" | awk -F'|' '{
        if (match($1, /UID=([0-9]+)/, a)) {
            uid = a[1];
            cmd = $2;
            "getent passwd " uid " | cut -d: -f1" | getline user;
            close("getent passwd " uid " | cut -d: -f1");
            print user " | " cmd;
        } else {
            print $2;
        }
    }' | sed '/^[[:space:]]*$/d' | sort -u | sed '/-[pP]/ s/^/'"$red"'/; /-[pP]/ s/$/'"$reset"'/'
    rm -f "$tmpfile"
}

FirewallRules () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                   Firewall Rules                  ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    
    printf "\n${CYAN}[+] Firewall Rules ${RESET}\n"
    find /etc /var -type f -exec grep -lE 'Generated by [a-zA-Z]*-save' {} + 2>/dev/null
}

CronJobs () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                     Cron Jobs                     ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    
    printf "\n${CYAN}[+] ls -lah /etc/cron* ${RESET}"
    ls -lah /etc/cron* | grep -v 'crontab' | grep -Ev "(\.|\.\.|\.placeholder|anacron|man-db)$" | grep -Ev "^total" | sed '$a\\' | sed '/^\/etc.*:$/ {N; /\n$/d; }' | sed '${/^$/d}'

    crontab_check=$(cat /etc/crontab | md5sum)
    if [[ $crontab_check == "44df62f8c671c9306af920e2839cda53"* ]]; then
        :
    elif [[ $crontab_check == "e34d8e317f0057ea65f179d5b35d699c"* ]]; then
        :
    else
        printf "\n${CYAN}[+] cat /etc/crontab ${RESET}"
        cat /etc/crontab | grep -Ev '(.|..)$'
    fi

    printf "\n${CYAN}[+] Cron Syslog ${RESET}\n"
    grep "CRON" /var/log/syslog | awk '{for (i=6; i<NF; i++) printf $i " "; print $NF}' |sort -u

    printf "\n${CYAN}[+] crontab -l ${RESET}\n"
    sudo_crontab=$(sudo -n crontab -l 2>&1)
    if [[ $sudo_crontab == *"sudo: a password is required" ]]; then
        crontab -l | grep -vE "^#"
    else
	printf "%s\n" "$sudo_crontab" | grep -vE "^#"
    fi

}

FilePermissions () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}              File System Permissions              ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"

    printf "\n${CYAN}[+] File Contains pass Keyword${RESET}\n"
       # File extensions to include in the search
    file_extensions="conf|ini|xml|json"
    
    # Directories to include in the search
    include_dirs="^(/etc/|/home/|/var/)"
    
    # Keywords to search for
    search_term="pass"
    
    # False positives to exclude
    false_positives="passenger|passport|base-passwd|passdown|passed|passes|pass through|pass a"
    
    # Paths to exclude from the final output
    exclude_paths="/doc/|/licenses/|/log/|/etc/apparmor/parser.conf|/etc/ca-certificates.conf|/etc/debconf.conf|/etc/e2scrub.conf|/etc/hdparm.conf|/etc/nsswitch.conf|/etc/security/faillock.conf|/etc/ltrace.conf|/etc/sos/sos.conf"
    
    # Main command as a one-liner

    plaintextpass=$(find / -type f -regextype posix-egrep -regex ".+\.($file_extensions)$" 2>/dev/null | xargs grep -in "pass" 2>/dev/null | awk -v false_positives="$false_positives" 'tolower($0) !~ tolower(false_positives) || /(^|[^a-zA-Z])pass([^a-zA-Z]|$).*(tolower(false_positives))|.*(tolower(false_positives)).*(^|[^a-zA-Z])pass([^a-zA-Z]|$)/' | awk -F: '{print $1}' | sort -u | grep -vE "($exclude_paths)" )
    
    # plaintextpass=$(find / -type f -regextype posix-egrep -regex ".+\.($file_extensions)$" 2>/dev/null | grep -E "$include_dirs" | xargs grep -in "pass" 2>/dev/null | awk -v false_positives="$false_positives" 'tolower($0) !~ tolower(false_positives) || /(^|[^a-zA-Z])pass([^a-zA-Z]|$).*(tolower(false_positives))|.*(tolower(false_positives)).*(^|[^a-zA-Z])pass([^a-zA-Z]|$)/' | awk -F: '{print $1}' | sort -u | grep -vE "($exclude_paths)" )
    printf "${YELLOW}$plaintextpass${RESET}\n"
    

    printf "\n${CYAN}[+] SUDO - https://gtfobins.github.io/#+sudo${RESET}\n"

    vulnsudo="(/7z|/aa-exec|/ab|/alpine|/ansible-playbook|/ansible-test|/aoss|/apache2ctl|/apt-get|/apt|/ar|/aria2c|/arj|/arp|/as|/ascii-xfr|/ascii85|/ash|/aspell|/at|/atobm|/awk|/aws|/base32|/base58|/base64|/basenc|/basez|/bash|/batcat|/bc|/bconsole|/bpftrace|/bridge|/bundle|/bundler|/busctl|/busybox|/byebug|/bzip2|/c89|/c99|/cabal|/capsh|/cat|/cdist|/certbot|/check_by_ssh|/check_cups|/check_log|/check_memory|/check_raid|/check_ssl_cert|/check_statusfile|/chmod|/choom|/chown|/chroot|/clamscan|/cmp|/cobc|/column|/comm|/composer|/cowsay|/cowthink|/cp|/cpan|/cpio|/cpulimit|/crash|/crontab|/csh|/csplit|/csvtool|/cupsfilter|/curl|/cut|/dash|/date|/dc|/dd|/debugfs|/dialog|/diff|/dig|/distcc|/dmesg|/dmidecode|/dmsetup|/dnf|/docker|/dosbox|/dotnet|/dpkg|/dstat|/dvips|/easy_install|/eb|/ed|/efax|/elvish|/emacs|/enscript|/env|/eqn|/espeak|/ex|/exiftool|/expand|/expect|/facter|/file|/find|/fish|/flock|/fmt|/fold|/fping|/ftp|/gawk|/gcc|/gcloud|/gcore|/gdb|/gem|/genie|/genisoimage|/ghc|/ghci|/gimp|/ginsh|/git|/grc|/grep|/gtester|/gzip|/hd|/head|/hexdump|/highlight|/hping3|/iconv|/iftop|/install|/ionice|/ip|/irb|/ispell|/jjs|/joe|/join|/journalctl|/jq|/jrunscript|/jtag|/julia|/knife|/ksh|/ksshell|/ksu|/kubectl|/latex|/latexmk|/ld.so|/ldconfig|/less|/lftp|/links|/ln|/loginctl|/logsave|/look|/ltrace|/lua|/lualatex|/luatex|/lwp-download|/lwp-request|/mail|/make|/man|/mawk|/minicom|/more|/mosquitto|/mount|/msfconsole|/msgattrib|/msgcat|/msgconv|/msgfilter|/msgmerge|/msguniq|/mtr|/multitime|/mv|/mysql|/nano|/nasm|/nawk|/nc|/ncdu|/ncftp|/neofetch|/nft|/nice|/nl|/nm|/nmap|/node|/nohup|/npm|/nroff|/nsenter|/ntpdate|/octave|/od|/openssl|/openvpn|/openvt|/opkg|/pandoc|/paste|/pdb|/pdflatex|/pdftex|/perf|/perl|/perlbug|/pexec|/pg|/php.*|/pic|/pico|/pidstat|/pip|/pkexec|/pkg|/posh|/pr|/pry|/psftp|/psql|/ptx|/puppet|/pwsh|/python|/rake|/rc|/readelf|/red|/redcarpet|/restic|/rev|/rlwrap|/rpm|/rpmdb|/rpmquery|/rpmverify|/rsync|/ruby|/run-mailcap|/run-parts|/runscript|/rview|/rvim|/sash|/scanmem|/scp|/screen|/script|/scrot|/sed|/service|/setarch|/setfacl|/setlock|/sftp|/sg|/shuf|/slsh|/smbclient|/snap|/socat|/soelim|/softlimit|/sort|/split|/sqlite3|/sqlmap|/ss|/ssh-agent|/ssh-keygen|/ssh-keyscan|/ssh|/sshpass|/start-stop-daemon|/stdbuf|/strace|/strings|/su|/sudo|/sysctl|/systemctl|/systemd-resolve|/tac|/tail|/tar|/task|/taskset|/tasksh|/tbl|/tclsh|/tcpdump|/tdbtool|/tee|/telnet|/terraform|/tex|/tftp|/tic|/time|/timedatectl|/timeout|/tmate|/tmux|/top|/torify|/torsocks|/troff|/ul|/unexpand|/uniq|/unshare|/unsquashfs|/unzip|/update-alternatives|/uudecode|/uuencode|/vagrant|/valgrind|/varnishncsa|/vi|/view|/vigr|/vim|/vimdiff|/vipw|/virsh|/w3m|/wall|/watch|/wc|/wget|/whiptail|/wireshark|/wish|/xargs|/xdg-user-dir|/xdotool|/xelatex|/xetex|/xmodmap|/xmore|/xpad|/xxd|/xz|/yarn|/yash|/yum|/zathura|/zip|/zsh|/zsoelim|/zypper)"

    adminaccount="(ALL : ALL) ALL"
    sudol=$(sudo -n -l | grep -A 5 "may run the following" | grep -v "may run the following" | sed 's/^\s*//g' | sed 's/, /\n/g' | sed 's/) \//)\n\//g')
    if [[ "$sudol" == "$adminaccount" ]]; then
	printf "${YELLOW}$sudol${RESET}  #admin account, try sudo -i\n"
    else
        echo "$sudol" | while IFS= read -r line; do
            if echo "$line" | grep -Eq "$vulnsudo"; then
                printf "${YELLOW}$line${RESET}\n"
            else
                printf "$line\n"
            fi
        done
    fi


    printf "\n${CYAN}[+] World Writable Folders ${RESET}\n"
    configfiles="(/etc/passwd/|/etc/group|/etc/fstab|/etc/profile|/etc/sudoers|/etc/shadow)"
    filestypes="(conf|sh|php|log|txt|ini|py|json|xml|yaml|env|pl|rb|js|cfg|sql|bak|old|out|so|bin|lib)"
    stickybit=$(find / -perm -1000 -type d 2>/dev/null)
    wwfolder=$(find / -writable -type d 2>/dev/null | sort -u | grep -vE "^(/dev/shm(/.*)?|/run/lock(/.*)?|/run/user/${userid}(/.*)?|/home/${user}(/.*)?)")
    wwfile=$(find / -type f -perm -o+w 2>/dev/null | grep -vE '^(/sys/|/proc|/dev/|/run/|/tmp/|/var/tmp/|/var/log/)' | grep -E "${filetypes}")

    for i in $wwfolder; do
        if echo "$stickybit" | grep -qw "$i"; then
	    printf "$i (sticky bit is set)\n"
        else
            printf "${YELLOW}$i${RESET}\n"
        fi
    done

    #printf "\n${CYAN}[+] World Executable Folders ${RESET}\n"
    #find / -type d -perm -o+x 2>/dev/null | sort -u | grep -vE "^(/sys/fs/cgroup(/.*)?|/proc(/.*)?|/dev/mqueue(/.*)?|/dev/shm(/.*)?|/run/lock(/.*)?|/run/user/[0-9]{4}(/.*)?|/home/${user}(/.*)?)"

    printf "\n${CYAN}[+] World Writable Files ${RESET}\n"
    for i in $wwfile; do
        if echo "$configfiles" | grep -qw "$i"; then
	    printf "${YELLOW}$i${RESET}\n"
	else
            printf "$i\n"
	fi
    done
    
    printf "\n${CYAN}[+] SUID Files - https://gtfobins.github.io/#+suid${RESET}\n"
    commonsuid="(/usr/bin/chfn|/usr/bin/chsh|/usr/bin/fusermount|/usr/bin/gpasswd|/usr/bin/mount|/usr/bin/newgrp|/usr/bin/passwd|/usr/bin/su|/usr/bin/sudo|/usr/bin/umount)"
    vulnsuids="(/aa-exec|/ab|/agetty|/alpine|/ar|/arj|/arp|/as|/ascii-xfr|/ash|/aspell|/atobm|/awk|/base32|/base64|/basenc|/basez|/bash|/bc|/bridge|/busctl|/busybox|/bzip2|/cabal|/capsh|/cat|/chmod|/choom|/chown|/chroot|/clamscan|/cmp|/column|/comm|/cp|/cpio|/cpulimit|/csh|/csplit|/csvtool|/cupsfilter|/curl|/cut|/dash|/date|/dd|/debugfs|/dialog|/diff|/dig|/distcc|/dmsetup|/docker|/dosbox|/ed|/efax|/elvish|/emacs|/env|/eqn|/espeak|/expand|/expect|/file|/find|/fish|/flock|/fmt|/fold|/gawk|/gcore|/gdb|/genie|/genisoimage|/gimp|/grep|/gtester|/gzip|/hd|/head|/hexdump|/highlight|/hping3|/iconv|/install|/ionice|/ip|/ispell|/jjs|/join|/jq|/jrunscript|/julia|/ksh|/ksshell|/kubectl|/ld.so|/less|/links|/logsave|/look|/lua|/make|/mawk|/minicom|/more|/mosquitto|/msgattrib|/msgcat|/msgconv|/msgfilter|/msgmerge|/msguniq|/multitime|/mv|/nasm|/nawk|/ncftp|/nft|/nice|/nl|/nm|/nmap|/node|/nohup|/ntpdate|/od|/openssl|/openvpn|/pandoc|/paste|/perf|/perl|/pexec|/pg|/php.*|/pidstat|/pr|/ptx|/python|/rc|/readelf|/restic|/rev|/rlwrap|/rsync|/rtorrent|/run-parts|/rview|/rvim|/sash|/scanmem|/sed|/setarch|/setfacl|/setlock|/shuf|/soelim|/softlimit|/sort|/sqlite3|/ss|/ssh-agent|/ssh-keygen|/ssh-keyscan|/sshpass|/start-stop-daemon|/stdbuf|/strace|/strings|/sysctl|/systemctl|/tac|/tail|/taskset|/tbl|/tclsh|/tee|/terraform|/tftp|/tic|/time|/timeout|/troff|/ul|/unexpand|/uniq|/unshare|/unsquashfs|/unzip|/update-alternatives|/uudecode|/uuencode|/vagrant|/varnishncsa|/view|/vigr|/vim|/vimdiff|/vipw|/w3m|/watch|/wc|/wget|/whiptail|/xargs|/xdotool|/xmodmap|/xmore|/xxd|/xz|/yash|/zsh|/zsoelim)"

    SUID=$(find / -perm -u=s -type f 2>/dev/null | sort -u | grep -vE $commonsuid)
    for i in $SUID; do 
        if echo "$i" | grep -Eq "$vulnsuids\$"; then
	    printf "${YELLOW}$i${RESET}\n"
        else 
            printf "$i\n"
        fi
    done	


    printf "\n${CYAN}[+] Linux Capabilities - https://gtfobins.github.io/#+capabilities${RESET}\n"
    vulncapabilities="(/gdb|/node|/perl|/php.*|/python|/ruby|/rview|/rvim|/view|/vim|/vimdiff)"
    capabilities=$(/usr/sbin/getcap -r / 2>/dev/null| awk '{print $1}')
    echo "$capabilities" | while IFS= read -r line; do
        if echo "$line" | grep -Eq "$vulncapabilities"; then
            printf "${YELLOW}$line${RESET}\n"
        else
            printf "$line\n"
        fi
    done

    printf "\n${CYAN}[+] SGID Files ${RESET}- run as the group, not the user who started it.\n"
    find / -perm -g=s -type f 2>/dev/null
    
    printf "\n${CYAN}[+] Sticky Bit ${RESET}- Only the owner of the directory or the owner of a file can delete or rename here.\n"
    printf "%s\n" "$stickybit"
}

Drives () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                      Drives                       ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    
    
    printf "\n${CYAN}[+] debugfs Check ${RESET}\n"
    df -lh | awk 'NR > 1 {print $1, $6}' | while read device mountpoint; do
        [[ $device != /dev/* ]] && continue

        if [[ -r "$device" ]]; then
            output=$(echo "ls /" | debugfs "$device" 2>&1)
    
            if [[ "$output" == *"debugfs:"* && "$output" != *"Bad magic number"* && "$output" != *"can't open"* ]]; then
                echo -e "    ${GREEN}[+] debugfs $device${NC}"
                echo "        ($mountpoint)"
            else
                echo -e "    ${RED}[-] debugfs $device${NC}"
                echo "        ($mountpoint)"
            fi
        else
            echo -e "${RED}[-] $device${NC}"
            echo "    ($mountpoint)"
        fi
    done
    
    printf "\n${CYAN}[+] Mounted File Systems ${RESET}\n"
    mount
    
    printf "\n${CYAN}[+] Mounted at Boot Time ${RESET}\n"
    cat /etc/fstab | grep -Ev "^#" | awk '{printf "%-42s %-15s %-15s %-20s %-5s %-0s\n", $1, $2, $3, $4, $5, $6 }'
    
    printf "\n${CYAN}[+] Available Disks ${RESET}\n"
    lsblk
}

KernelModules () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                  Kernel Modules                   ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    
    printf "\n${CYAN}[+] Loaded Modules ${RESET}\n"
    modules=$(lsmod | awk '{print $1}' | grep -v "^Module" | sort -u)
    for i in $modules; do 
	    # modinfo=$(/sbin/modinfo $i 2>/dev/null | grep -E '^filename:|^version:' | awk '{print $2}' | sed ':a;N;$!ba;s/\n/  /g' | awk '{printf "%-10s %-0s\n", $2, $1}')
	    modversion=$(/sbin/modinfo $i 2>/dev/null | grep -E '^version:' | awk '{print $2}')
	    modpath=$(/sbin/modinfo $i 2>/dev/null | grep -E '^filename:' | awk '{print $2}')
	    printf "%s\n" "$i"
	    printf "%s\n" "    Version:$modversion"
	    printf "%s\n" "    Filename:$modpath"
	    printf "\n"
    done
}

CVE () {
    printf "\n${CYAN}===================================================${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${BLUE}${WHITEBG}                  CVE Check                        ${RESET}\n"
    printf "${WHITEBG}                                                   ${RESET}\n"
    printf "${CYAN}===================================================${RESET}\n"
    
    pkexec=$(which pkexec)
    if [[ pkexec != NULL ]]; then
       cve_2021_4034=$($pkexec --version | awk '{print $NF}')
       pkexec_safe="0.120"
       if [[ $cve_2021_4034 < $pkexec_safe ]]; then  
           printf "\n${CYAN}[+] CVE-2021-4034${RESET}"
           printf "\n${YELLOW}$pkexec $cve_2021_4034${RESET} - https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c\n"

       fi
    fi
}

# Execute functions based on flags
echo -e "\n${GREEN}Executing Selected Recon Functions...${RESET}"
[[ $EnableSystemInfo == true ]] && SystemInfo
[[ $EnableUsers == true ]] && Users
[[ $EnableNetworks == true ]] && Networks
[[ $EnableRunningProcesses == true ]] && RunningProcesses
[[ $EnableFirewallRules == true ]] && FirewallRules
[[ $EnableCronJobs == true ]] && CronJobs
[[ $EnableFilePermissions == true ]] && FilePermissions
[[ $EnableDrives == true ]] && Drives
[[ $EnableKernelModules == true ]] && KernelModules
[[ $EnableCVE == true ]] && CVE
printf "\n"
