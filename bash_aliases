## make wget continue by default
alias wget='wget -c'

## set some other defaults ##
alias df='df -H'
alias du='du -ch'
 
# top is atop, just like vi is vim
alias top='atop'
 
## nfsrestart  - must be root  ##
## refresh nfs mount / cache etc for Apache ##
alias nfsrestart='sync && sleep 2 && /etc/init.d/httpd stop && umount netapp2:/exports/http && sleep 2 && mount -o rw,sync,rsize=32768,wsize=32768,intr,hard,proto=tcp,fsc natapp2:/exports /http/var/www/html &&  /etc/init.d/httpd start'
 
## Memcached server status  ##
alias mcdstats='/usr/bin/memcached-tool 10.10.27.11:11211 stats'
alias mcdshow='/usr/bin/memcached-tool 10.10.27.11:11211 display'
 
## quickly flush out memcached server ##
alias flushmcd='echo "flush_all" | nc 10.10.27.11 11211'
 
## Remove assets quickly from Akamai / Amazon cdn ##
alias cdndel='/home/scripts/admin/cdn/purge_cdn_cache --profile akamai'
alias amzcdndel='/home/scripts/admin/cdn/purge_cdn_cache --profile amazon'
 
## supply list of urls via file or stdin
alias cdnmdel='/home/scripts/admin/cdn/purge_cdn_cache --profile akamai --stdin'
alias amzcdnmdel='/home/scripts/admin/cdn/purge_cdn_cache --profile amazon --stdin'

## pass options to free ##
alias meminfo='free -m -l -t'
 
## get top process eating memory
alias psmem='ps auxf | sort -nr -k 4'
alias psmem10='ps auxf | sort -nr -k 4 | head -10'
 
## get top process eating cpu ##
alias pscpu='ps auxf | sort -nr -k 3'
alias pscpu10='ps auxf | sort -nr -k 3 | head -10'
 
## Get server cpu info ##
alias cpuinfo='lscpu'
 
## older system use /proc/cpuinfo ##
##alias cpuinfo='less /proc/cpuinfo' ##
 
## get GPU ram on desktop / laptop##
alias gpumeminfo='grep -i --color memory /var/log/Xorg.0.log'

## shortcut  for iptables and pass it via sudo#
alias ipt='sudo /sbin/iptables'
 
# display all rules #
alias iptlist='sudo /sbin/iptables -L -n -v --line-numbers'
alias iptlistin='sudo /sbin/iptables -L INPUT -n -v --line-numbers'
alias iptlistout='sudo /sbin/iptables -L OUTPUT -n -v --line-numbers'
alias iptlistfw='sudo /sbin/iptables -L FORWARD -n -v --line-numbers'
alias firewall=iptlist

alias ports='netstat -tulanp'

# Stop after sending count ECHO_REQUEST packets #
alias ping='ping -c 5'
# Do not wait interval 1 second, go fast #
alias fastping='ping -c 100 -s.2'

## Colorize the grep command output for ease of use (good for log files)##
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

alias ss='searchsploit $1'
alias ssx='searchsploit -x $1'
alias ssm='searchsploit -m $1'
alias gobusterz='gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -u $1'
alias mscanz='sudo masscan -p1-65535,U:1-65535 $1 --rate=1000 -e tun0 --wait 5 > mscan.txt'
alias nmapz='/home/crystal/scripts/gen_nmap.py; while read item; do sudo nmap -sV -sC -sU -sS $item; done < nmap.txt; rm mscan.txt nmap.txt'
alias qmapz='sudo nmap -sV -sC $1'
alias nse='ls /usr/share/nmap/scripts | grep'
alias nse-help='nmap --script-help'
alias pattern_create='/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l $1'
alias pattern_offset='/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q $1' 
alias nasm_shell='/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb'
alias msfelfscan='/usr/share/framework2/msfelfscan'
alias wpscan='wpscan -e ap,t,u --api-token <no_stealing_cats_tokens> --url $1'
alias wes-ng='python /home/crystal/scripts/windows/wesng/wes.py'
alias aslr_off='echo 0 | sudo tee /proc/sys/kernel/randomize_va_space'
alias gen_nmap='/home/crystal/scripts/gen_nmap.py'
alias gcc_no_protections='gcc -fno-stack-protector -z execstack -no-pie'
alias dvwa_start='sudo service mysql start && sudo service apache2 start'
alias docker_fix='sudo mkdir /sys/fs/cgroup/systemd; sudo mount -t cgroup -o none,name=systemd cgroup /sys/fs/cgroup/systemd'
alias android_studio='/home/crystal/apps/android-studio/bin/studio.sh'
alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:1.10.0'
alias pipz_upgrade='pip freeze > requirements.txt; pip install -r requirements.txt --upgrade; rm requirements.txt;'
alias ghidra_auto='python3 /home/crystal/apps/auto_ghidra.py'
alias pwninit='/home/crystal/apps/pwninit --template-path ~/.config/pwninit-template.py; sed -n "4,6p" solve.py; rm solve.py; mv *_patched $1'
alias burpsuite='java -jar --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED /usr/bin/burpsuite'
alias ctfd_download='python ~/ctf/helpers/ctfd_download_python/download.py'
alias enum4linux='python /home/crystal/scripts/enum4linux-ng/enum4linux-ng.py'
alias subbrute='python /home/crystal/apps/subbrute/subbrute.py'
alias mobsf_emulator='emulator -avd $1 -writable-system -no-snapshot'
alias codemerx='/home/crystal/apps/codemerx/bin/CodemerxDecompile'
alias webdavup='sudo wsgidav --host=$1 --port=$2 --root=/tmp --auth=anonymous'
alias username-anarchy='ruby /home/crystal/apps/username-anarchy/username-anarchy'
alias xs-strike='python /home/crystal/apps/XSStrike/xsstrike.py'
alias jwt_tool='python /home/crystal/apps/jwt_tool/jwt_tool.py'

ffuf-vhost() {
    arg_count=3
    if [[ $2 && $2 != -* ]]; then
        wordlist=$2
    else
        wordlist='/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'
        arg_count=2
    fi
    ffuf -c -H "Host: FUZZ.$1" -u http://$1 -w $wordlist ${@: $arg_count};
}
ffuf-dir() {
    arg_count=3
    if [[ $2 && $2 != -* ]]; then
        wordlist=$2
    else
        wordlist='/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt'
        arg_count=2
    fi
    ffuf -c -u $1FUZZ -w $wordlist ${@: $arg_count};
}
ffuf-req() {
    arg_count=2
    if [[ $1 && $1 != -* ]]; then
        wordlist=$1
    else
        wordlist='/usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt'
        arg_count=1
    fi
    ffuf -c -ic -request new.req -request-proto http -w $wordlist ${@: $arg_count};
}
plzsh() {
    if [[ $1 ]]; then
        port=$1
    else
        port=1337
    fi
    stty raw -echo; (echo 'python3 -c "import pty;pty.spawn(\"/bin/bash\")" || python -c "import pty;pty.spawn(\"/bin/bash\")"' ;echo "stty$(stty -a | awk -F ';' '{print $2 $3}' | head -n 1)"; echo reset;cat) | nc -lvnp $port && reset
}
qssh() {
    sshpass -p $2 ssh -o StrictHostKeyChecking=no $1@$3 ${@: 4};
}
