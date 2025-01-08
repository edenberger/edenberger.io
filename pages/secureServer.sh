#!/usr/bin/env bash
set +e
# Accept debug and verbose flags
VERBOSE="&>/dev/null"
grep -q -e " -d " -e " --debug " -e " -v " -e " --verbose " <<< "${@}" && { set -x; PS4='$LINENO: '; VERBOSE="" ; }

# WARNING:
# NOT FOR PRODUCTION AS-IS
#
# Description:
# This script meant to harden CentOS-7
# Part of hardening is disable the option to act as a router
# Another part is to remove X Window System (GUI), if you want to keep the GUI please use -g or --gui flag
#
# Some notes:
# We disable ssh banner altough the harden manual suggests to use it
# We keep IPv6 enabled
# Unroutable source address packets are being logged
# If running this script on a router, please inspect carefully Network section
# Page 155: Disable source routed packets, only affects dual inet interface systems configured as a router
# Important packages that being removed: openldap-clients
# Important services that being Disabled: nfs nfs-server rpcbind named dovecot smb snmpd
# Important services that we keep enabled: httpd rsyncd
#
# TODO:
# Incomplete: iptables-save and tests, user password hardening
# page 34 harden gdm
#

function sendLog () {
  echo "$1"
  logger secureServer: "$1"
}

function disableModule () {
  echo "install $1 /bin/true" >> /etc/modprobe.d/CIS.conf
  rmmod $1 $VERBOSE
}

function checkLsmod () {
  if [[ $(lsmod |grep $1 &>/dev/null ; echo $?) != 1 ]];then
    sendLog "$1 module is loaded! Please remove it"
    EXIT_CODE=1
  fi
}

EXIT_CODE=0

  # Clearing main modprobe file in order to refill it
> /etc/modprobe.d/CIS.conf

  # Disabling unneeded filesystems
disableModule cramfs
disableModule freevxfs
disableModule jffs2
disableModule hfs
disableModule hfsplus
disableModule squashfs
disableModule udf

checkLsmod cramfs
checkLsmod freevxfs
checkLsmod jffs2
checkLsmod hfs
checkLsmod hfsplus
checkLsmod squashfs
checkLsmod udf

  # Check options on /dev/shm (shared memory) mount
if [[ $(grep "nodev\|nosuid\|noexec" <(mount |grep /dev/shm) &>/dev/null ; echo $?) == 0 ]];then
  sendLog "/dev/shm is mounted without nodev, nosuid or noexec, Please change fstab to the right options"
  mount |grep /dev/shm
  EXIT_CODE=1
fi

  # Make sure /dev/shm is in fstab with the right options
if [[ $(grep /dev/shm /etc/fstab &>/dev/null ; echo $?) == 0 ]];then
  grep -v /dev/shm /etc/fstab > ~/fstab.temp
  echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> ~/fstab.temp
  mv -f ~/fstab.temp /etc/fstab
else
  echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
fi

  # Scan for world writable directories without the sticky bit
df --local -P |awk {'if (NR!=1) print $6'} |xargs -I '{}' find '{}' -xdev -type d -perm -0002 |xargs chmod a+t

if [[ $(df --local -P |awk {'if (NR!=1) print $6'} |xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) |wc -l) > 0 ]];then
  sendLog "There are still world writable directories without the sticky bit on them:"
  df --local -P |awk {'if (NR!=1) print $6'} |xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)
  EXIT_CODE=1
fi

  # Disable Autofs (altough it's not there)
systemctl disable autofs $VERBOSE
systemctl stop autofs $VERBOSE
rpm -e --nodeps autofs $VERBOSE

  # Check for repositories which doesn't use gpg
if [[ $(grep ^gpgcheck /etc/yum.conf /etc/yum.repos.d/* |grep -v gpgcheck=1 |wc -l) != 0 ]];then
  sendLog "Found repositories with gpgcheck off:"
  grep -n ^gpgcheck /etc/yum.conf /etc/yum.repos.d/* |grep -v gpgcheck=1
  EXIT_CODE=1
fi

  ## Adding a password for grub2
  # Remove current password
touch /boot/grub2/user.cfg
sed -i '/^GRUB2_PASSWORD=/d' /boot/grub2/user.cfg
  # Add new password
echo 'GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.F40369BE861FA50A36BC6B447A8770843F89EC3D3B4CAA1FE08B76136E1E27A72A388DA41BE7644300522B7BAD5F50F0EC1B298BD2673740DE1447EB97D304CC.1DB8FB16CE297FC5702C4BD4FF7F7E2E97417F35F1029C15EB1970AB8C6B85BE999F77863150A7C0BCE2025B3441FAABC644D69E699E482DA2324455DC2F8BE4' >> /boot/grub2/user.cfg

  # Change permissions on /boot/grub2/grub.cfg
chown root.root /boot/grub2/grub.cfg $VERBOSE
chmod og-rwx /boot/grub2/grub.cfg $VERBOSE

  # Check permissions on /boot/grub2/grub.cfg
if [[ $(find /boot/grub2/grub.cfg -type f -group root -user root -perm 0600 |wc -l) != 1 ]];then
  sendLog "Found different permissions/owner on /boot/grub2/grub.cfg, Please check"
  EXIT_CODE=1
fi

  # Check perms on /boot/grub2/user.cfg
chown root.root /boot/grub2/user.cfg $VERBOSE
chmod og-rwx /boot/grub2/user.cfg $VERBOSE

  # Check permissions on /boot/grub2/user.cfg
if [[ $(find /boot/grub2/user.cfg -type f -group root -user root -perm 0600 |wc -l) != 1 ]];then
  sendLog "Found different permissions/owner on /boot/grub2/user.cfg, Please check"
  EXIT_CODE=1
fi

  ## Make sure rescue and emergency ask a password
  # Rescue.service
sed -i '/ExecStart=/d' /usr/lib/systemd/system/rescue.service
echo 'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' >> /usr/lib/systemd/system/rescue.service

if [[ $(grep 'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"$' /usr/lib/systemd/system/rescue.service &>/dev/null ; echo $?) != 0 ]];then
  sendLog "Found different ExecStart command on rescue.service, Please check"
  EXIT_CODE=1
fi

  # Emergency.service
sed -i '/ExecStart=/d' /usr/lib/systemd/system/emergency.service
echo 'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"' >> /usr/lib/systemd/system/emergency.service

if [[ $(grep 'ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"$' /usr/lib/systemd/system/emergency.service &>/dev/null ; echo $?) != 0 ]];then
  sendLog "Found different ExecStart command on emergency.service, Please check"
  EXIT_CODE=1
fi

  ## Disable core dumps
echo -- '* hard core 0' > /etc/security/limits.d/00-no-dumps.conf
echo 'fs.suid_dumpable = 0' > /etc/sysctl.d/01-no-dumps.conf
sysctl -w fs.suid_dumpable=0 $VERBOSE

if [[ $(grep "hard core" /etc/security/limits.conf /etc/security/limits.d/* &>/dev/null ; echo $?) != 0 ]];then
  sendLog 'No "hard core 0" in limits.conf (or limits.d/*), Please check'
  EXIT_CODE=1
fi

  ## ASLR
echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/02-enable-ASLR.conf
sysctl -w kernel.randomize_va_space=2 $VERBOSE
if [[ $(grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* &>/dev/null ; echo $?) != 0 ]];then
  sendLog "ASLR isn't configured in /etc/sysctl.* and /etc/sysctl.d/* (doesn't means it isn't enabled), Please check"
  EXIT_CODE=1
fi

  ## Remove prelink, failing on purpose
prelink -ua &>/dev/null
yum -y remove prelink &>/dev/null

  ## Clean motd
> /etc/motd

if [[ $(cat /etc/motd|wc -l) != 0 ]];then
  sendLog "Unable to modify /etc/motd, Please check"
  EXIT_STATUS=1
fi

  ## Check permissions on /etc/issue
chown root.root /etc/issue &>/dev/null
chmod 0644 /etc/issue &>/dev/null

if [[ $(find /etc/issue -type f -group root -user root -perm 0644 |wc -l) != 1 ]];then
  sendLog "Wrong permissions on /etc/issue, Please check"
  EXIT_CODE=1
fi

  # Install security updates TODO: set the time
crontab <(crontab -l 2>/dev/null|grep -v "^0 \* \* \* \* yum update --security -y &>/dev/null$" ; echo "0 * * * * yum update --security -y &>/dev/null")

if [[ $(crontab -l 2>/dev/null|grep "^0 \* \* \* \* yum update --security -y &>/dev/null$" &>/dev/null ; echo $?) != 0 ]];then
  sendLog "Cron job to update security updates isn't active, Please check"
  EXIT_CODE=1
fi

  # Disable unneeded services (TODO: check if they exists)
badServices="$(systemctl list-unit-files|grep -ioE .*avahi.[a-z]+|tr '\n' ' ') \
  chargen chargen-dgram chargen-stream daytime daytime-dgram daytime-stream discard \
  discard-dgram discard-stream echo echo-dgram echo-stream time time-dgram time-stream \
  tftp-server tftp xinetd cups dhcpd slapd nfs nfs-server rpcbind named vsftpd \
  dovecot smb squid snmpd ypserv rsh rlogin rexec telnet tftp ntalk"

for service in $badServices ;do
  chkconfig $service off &>/dev/null
  systemctl disable $service &>/dev/null
  systemctl stop $service &>/dev/null
done

  ## Remove unneeded packages
badPackages="rsh talk telnet openldap-clients"

for package in $badPackages ;do
  yum -y remove $package &>/dev/null
done

  ## Remove NIS client
rpm -e --nodeps ypbind yp-tools &>/dev/null

  ## NTP. configure restrictions and server address
  # Remove all lines match ^restrict
sed -i '/^restrict/d' /etc/ntp.conf &>/dev/null
  # Add restrictions to both IP versions
echo -e "restrict -4 default kod nomodify notrap nopeer noquery\n\
restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf

sed -i '/^server/d' /etc/ntp.conf &>/dev/null
sed -i '/^pool/d' /etc/ntp.conf &>/dev/null

echo -e "server 0.centos.pool.ntp.org iburst\n
server 1.centos.pool.ntp.org iburst" >> /etc/ntp.conf
  # Set ntp daemon user & group
echo 'OPTIONS="-u ntp:ntp"' > /etc/sysconfig/ntpd

if [[ $(grep "^restrict -4 default kod nomodify notrap nopeer noquery$" /etc/ntp.conf &>/dev/null;echo $?) != 0 ]];then
  sendLog 'ntp restrictions are not (exactly): "restrict -4 default kod nomodify notrap nopeer noquery"'
  EXIT_CODE=1
fi

if [[ $(grep "^server 0.centos.pool.ntp.org iburst$" /etc/ntp.conf &>/dev/null;echo $?) != 0 ]];then
  sendLog "ntp server isn't configured to use 0.centos.pool.ntp.org"
  EXIT_CODE=1
fi

if [[ $(grep "^server 1.centos.pool.ntp.org iburst$" /etc/ntp.conf &>/dev/null;echo $?) != 0 ]];then
  sendLog "ntp server isn't configured to use 1.centos.pool.ntp.org"
  EXIT_CODE=1
fi

if [[ $(grep '^OPTIONS="-u ntp:ntp"' /etc/sysconfig/ntpd &>/dev/null ; echo $?) != 0 ]];then
  sendLog 'ntp service file is not ^OPTIONS="-u ntp:ntp", Please check'
  EXIT_CODE=1
fi

  ## Chrony set server and service options

sed -i '/^server/d' /etc/chrony.conf &>/dev/null
sed -i '/^pool/d' /etc/chrony.conf &>/dev/null

echo -e "server 0.centos.pool.ntp.org iburst\n
server 1.centos.pool.ntp.org iburst" >> /etc/chrony.conf

echo 'OPTIONS="-u chrony"' > /etc/sysconfig/chrony

if [[ $(grep "^server 0.centos.pool.ntp.org iburst$" /etc/chrony.conf &>/dev/null;echo $?) != 0 ]];then
  sendLog "chrony server isn't configured to use 0.centos.pool.ntp.org"
  EXIT_CODE=1
fi

if [[ $(grep "^server 1.centos.pool.ntp.org iburst$" /etc/chrony.conf &>/dev/null;echo $?) != 0 ]];then
  sendLog "Chrony server isn't configured to use 1.centos.pool.ntp.org"
  EXIT_CODE=1
fi

if [[ $(grep '^OPTIONS="-u chrony"' /etc/sysconfig/chrony &>/dev/null;echo $?) != 0 ]];then
  sendLog 'Chrony service file is not ^OPTIONS="-u chrony", Please check'
  EXIT_CODE=1
fi

  ## Remove X Window System (GUI) unless -g or --gui flags were given
if [[ $(echo $@ |grep -x -- "-g\|--gui" &>/dev/null ; echo $?) == 1 ]];then
  rpm -e --nodeps $(rpm -qa xorg-x11*) &>/dev/null

  if [[ $(rpm -qa|grep xorg-x11* &>/dev/null ; echo $?) == 0 ]];then
    sendLog "X Windows system is installed, Please check"
    EXIT_CODE=1
  fi
fi


  ## Postfix accept only local
sed -i '/^inet_interfaces/d' /etc/postfix/main.cf

echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf

systemctl restart postfix

if [[ $(postconf |grep loopback-only &>/dev/null ; echo $?) != 0 ]];then
  sendLog "Postfix isn't configured to listen to loopback-only, Please check"
  EXIT_CODE=1
fi



  ## Network
  # Disable IP forward
sysctl -w net.ipv4.ip_forward=0 &>/dev/null

echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/03-disable-ip-forward.conf

if [[ $(sysctl net.ipv4.ip_forward|tail -c2) != 0 ]];then
  sendLog "IP forward is still on, Please check"
  EXIT_CODE=1
fi

  # Disable source routed packets (page 155)
echo 'net.ipv4.conf.all.accept_source_route = 0' > /etc/sysctl.d/04-dis-accept-source-route.conf
echo 'net.ipv4.conf.default.accept_source_route = 0' >> /etc/sysctl.d/04-dis-accept-source-route.conf

sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null
sysctl -w net.ipv4.conf.default.accept_source_route=0 &>/dev/null

if [[ $(sysctl net.ipv4.conf.all.accept_source_route|tail -c2) != 0 ]];then
  sendLog "System accepts source routed packets, Please check"
  EXIT_CODE=1
fi

if [[ $(sysctl net.ipv4.conf.default.accept_source_route|tail -c2) != 0 ]];then
  sendLog "ICMP accepts source routed packets, Please check"
  EXIT_CODE=1
fi


  # Disable ICMP send redirects
echo 'net.ipv4.conf.all.send_redirects = 0' > /etc/sysctl.d/05-dis-send-icmp-redirects.conf
echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.d/05-dis-send-icmp-redirects.conf

sysctl -w net.ipv4.conf.all.send_redirects=0 &>/dev/null
sysctl -w net.ipv4.conf.default.send_redirects=0 &>/dev/null

if [[ $(sysctl net.ipv4.conf.all.send_redirects|tail -c2) != 0 ]];then
  sendLog "ICMP send redirects are not disabled, Please check"
  EXIT_CODE=1
fi

if [[ $(sysctl net.ipv4.conf.default.send_redirects|tail -c2) != 0 ]];then
  sendLog "ICMP send redirects are not disabled, Please check"
  EXIT_CODE=1
fi


  # Disable ICMP accept redirects
echo 'net.ipv4.conf.all.accept_redirects = 0' > /etc/sysctl.d/06-dis-accept-icmp-redirects.conf
echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.d/06-dis-accept-icmp-redirects.conf

sysctl -w net.ipv4.conf.all.accept_redirects=0 &>/dev/null
sysctl -w net.ipv4.conf.default.accept_redirects=0 &>/dev/null

if [[ $(sysctl net.ipv4.conf.all.accept_redirects|tail -c2) != 0 ]];then
  sendLog "ICMP accept redirects are not disabled, Please check"
  EXIT_CODE=1
fi

if [[ $(sysctl net.ipv4.conf.default.accept_redirects|tail -c2) != 0 ]];then
  sendLog "ICMP accept redirects are not disabled, Please check"
  EXIT_CODE=1
fi

  # Disable ICMP secure redirects
echo 'net.ipv4.conf.all.secure_redirects = 0' > /etc/sysctl.d/07-dis-secure-icmp-redirects.conf
echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/sysctl.d/07-dis-secure-icmp-redirects.conf

sysctl -w net.ipv4.conf.all.secure_redirects=0 &>/dev/null
sysctl -w net.ipv4.conf.default.secure_redirects=0 &>/dev/null

if [[ $(sysctl net.ipv4.conf.all.secure_redirects|tail -c2) != 0 ]];then
  sendLog "ICMP secure redirects are not disabled, Please check"
  EXIT_CODE=1
fi

if [[ $(sysctl net.ipv4.conf.default.secure_redirects|tail -c2) != 0 ]];then
  sendLog "ICMP secure redirects are not disabled, Please check"
  EXIT_CODE=1
fi

  # Log un-routable source address packets
echo 'net.ipv4.conf.all.log_martians = 1' > /etc/sysctl.d/08-log-unrouteable-packets.conf
echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.d/08-log-unrouteable-packets.conf

sysctl -w net.ipv4.conf.all.log_martians=1 &>/dev/null
sysctl -w net.ipv4.conf.default.log_martians=1 &>/dev/null

if [[ $(sysctl net.ipv4.conf.all.log_martians|tail -c2) != 1 ]];then
  sendLog 'System does not log "unroutable source address" packets, Please check'
  EXIT_CODE=1
fi

if [[ $(sysctl net.ipv4.conf.default.log_martians|tail -c2) != 1 ]];then
  sendLog 'System does not log "unroutable source address" packets, Please check'
  EXIT_CODE=1
fi

  # Ignore broadcast ICMP requests
echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' > /etc/sysctl.d/09-ignore-broadcasts.conf

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 &>/dev/null

if [[ $(sysctl net.ipv4.icmp_echo_ignore_broadcasts|tail -c2) != 1 ]];then
  sendLog 'System does not ignore broadcast ICMP requests, Please check'
  EXIT_CODE=1
fi

  # Ignore broadcast ICMP requests
echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' > /etc/sysctl.d/10-ignore_bogus_error.conf

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses &>/dev/null

if [[ $(sysctl net.ipv4.icmp_ignore_bogus_error_responses|tail -c2) != 1 ]];then
  sendLog 'The kernel is logging bogus error responses, Please check'
  EXIT_CODE=1
fi

  # Force reverse path filtering
echo 'net.ipv4.conf.all.rp_filter = 1' > /etc/sysctl.d/11-force-rp-filter.conf
echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.d/11-force-rp-filter.conf

sysctl -w net.ipv4.conf.all.rp_filter=1 &>/dev/null
sysctl -w net.ipv4.conf.default.rp_filter=1 &>/dev/null

if [[ $(sysctl net.ipv4.conf.all.rp_filter|tail -c2) != 1 ]];then
  sendLog 'The kernel is not configured to check the packets reverse path (where they came from/where they go), Please check'
  EXIT_CODE=1
fi

if [[ $(sysctl net.ipv4.conf.default.rp_filter|tail -c2) != 1 ]];then
  sendLog 'The kernel is not configured to check the packets reverse path (where they came from/where they go), Please check'
  EXIT_CODE=1
fi

  # Completely disallow IPv6
#echo 'net.ipv6.conf.all.disable_ipv6 = 1' > /etc/sysctl.d/12-disable-ipv6.conf
#echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.d/12-disable-ipv6.conf

#sysctl -w net.ipv6.conf.all.disable_ipv6=1 &>/dev/null
#sysctl -w net.ipv6.conf.default.disable_ipv6=1 &>/dev/null

#if [[ $(sysctl net.ipv6.conf.all.disable_ipv6|tail -c2) != 1 ]];then
#  sendLog 'IPv6 seems to be enabled, Please check'
#  EXIT_CODE=1
#fi

#if [[ $(sysctl net.ipv6.conf.default.disable_ipv6|tail -c2) != 1 ]];then
#  sendLog 'IPv6 seems to be enabled, Please check'
#  EXIT_CODE=1
#fi

sysctl -w net.ipv4.route.flush=1 &>/dev/null

  ## Install tcp wrappers
  # Check if a service use it with ldd <path to bin> |grep libwrap.so
yum -y install tcp_wrappers &>/dev/null

if [[ $(rpm -q tcp_wrappers-libs &>/dev/null;echo $?) != 0 ]];then
  sendLog "tcp_wrappers-libs is not install, Please check"
  EXIT_CODE=1
fi
if [[ $(rpm -q tcp_wrappers &>/dev/null;echo $?) != 0 ]];then
  sendLog "tcp_wrappers is not install, Please check"
  EXIT_CODE=1
fi


  ## Harden /etc/hosts.{allow,deny}. Choose one:
  # Deny everyone
#echo 'ALL: ALL' > /etc/hosts.deny
  # Allow one range
#echo 'ALL: CHANGE_ME_192.168.0.0/255.255.255.0' > /etc/hosts.allow
  # Allow two ranges
#echo 'ALL: CHANGE_ME_192.168.0.0/255.255.255.0, CHANGE_ME_192.168.1.0/255.255.255.0' > /etc/hosts.allow


chown root.root /etc/hosts.allow &>/dev/null
chmod 0644 /etc/hosts.allow &>/dev/null

chown root.root /etc/hosts.deny &>/dev/null
chmod 0644 /etc/hosts.deny &>/dev/null

  ## iptables rules

  #iptables -F

#iptables -P INPUT DROP
#iptables -P OUTPUT DROP
#iptables -P FORWARD DROP

  # Allow only loop-back interface communicate with 127.0.0.0/8
#iptables -A INPUT -i lo -j ACCEPT
#iptables -A OUTPUT -o lo -j ACCEPT
#iptables -A INPUT -s 127.0.0.0/8 -j DROP

#iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT


  ## Logging
  # Install rsyslog and syslog-ng (syslog-ng is in EPEL repository)
yum -y install rsyslog &>/dev/null
yum -y install syslog-ng &>/dev/null
  # Force permissions
echo '$FileCreateMode 0640' > /etc/rsyslog.d/new-files-permissions.cfg
find /var/log/ -type f -exec chmod 0640 {} \; &>/dev/null

systemctl restart rsyslog

if [[ $(grep '$FileCreateMode 0640' /etc/rsyslog.d/*.cfg &>/dev/null;echo $?) != 0 ]];then
  echo "Check rsyslog new files permissions"
  checkLog "Check rsyslog new files permissions"
  EXIT_CODE=1
fi

if [[ $(find /var/log -type f -not -perm 0640 |wc -l) != 0 ]];then
  echo "There are log files with different permissions than 0640:"
  checkLog "There are log files with different permissions than 0640:"
  find /var/log/ -type f -not -perm 0640
  EXIT_CODE=1
fi

function changePerms () {
  chown root.root $1 &>/dev/null
  chmod 0600 $1 &>/dev/null
}

function checkPerms () {
  if [[ -e $1 ]];then
    if [[ $(find $1 -user root -group root -perm 0600|wc -l) != 1 ]];then
      echo "File $1 does not have right permissions (0600):"
      checkLog "File $1 does not have right permissions (0600):"
      ls -l $1
      EXIT_CODE=1
    fi
  fi
}

changePerms /etc/crontab
changePerms /etc/cron.hourly
changePerms /etc/cron.daily
changePerms /etc/cron.weekly
changePerms /etc/cron.mountly
changePerms /etc/cron.deny
changePerms /etc/cron.allow
changePerms /etc/at.deny
changePerms /etc/at.allow

checkPerms /etc/crontab
checkPerms /etc/cron.hourly
checkPerms /etc/cron.daily
checkPerms /etc/cron.weekly
checkPerms /etc/cron.mountly
checkPerms /etc/cron.deny
checkPerms /etc/cron.allow
checkPerms /etc/at.deny
checkPerms /etc/at.allow

changePerms /etc/ssh/sshd_config
checkPerms /etc/ssh/sshd_config


sed -i '/^Protocol 2/d' /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config

sed -i '/^LogLevel/d' /etc/ssh/sshd_config
echo "LogLevel INFO" >> /etc/ssh/sshd_config

sed -i '/^X11Forwarding/d' /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config

sed -i '/^MaxAuthTries/d' /etc/ssh/sshd_config
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config

sed -i '/^IgnoreRhosts/d' /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

sed -i '/^HostbasedAuthentication/d' /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config

sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config

sed -i '/^MACs/d' /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config

sed -i '/^LoginGraceTime/d' /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config

#sed -i '/^Banner/d' /etc/ssh/sshd_config
#echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

  ## Harden password policy
sed -i '/^minlen/d' /etc/security/pwquality.conf
echo "minlen = 14" >> /etc/security/pwquality.conf

sed -i '/^dcredit/d' /etc/security/pwquality.conf
echo "dcredit = -1" >> /etc/security/pwquality.conf

sed -i '/^ucredit/d' /etc/security/pwquality.conf
echo "ucredit = -1" >> /etc/security/pwquality.conf

sed -i '/^ocredit/d' /etc/security/pwquality.conf
echo "ocredit = -1" >> /etc/security/pwquality.conf

sed -i '/^lcredit/d' /etc/security/pwquality.conf
echo "lcredit = -1" >> /etc/security/pwquality.conf


if [[ $(grep "^minlen" /etc/security/pwquality.conf|tail -c3) -lt 14 ]];then
  echo "Minimum length of passwords is less than 14, Please check"
  EXIT_CODE=1
fi

if [[ $(grep "^dcredit = -1$" /etc/security/pwquality.conf &>/dev/null ; echo $?) != 0 ]];then
  echo "Password quality is not configured to use at least one digit"
  EXIT_CODE=1
fi

if [[ $(grep "^lcredit = -1$" /etc/security/pwquality.conf &>/dev/null ; echo $?) != 0 ]];then
  echo "Password quality is not configured to use at least one lowercase letter"
  EXIT_CODE=1
fi

if [[ $(grep "^ucredit = -1$" /etc/security/pwquality.conf &>/dev/null ; echo $?) != 0 ]];then
  echo "Password quality is not configured to use at least one uppercase letter"
  EXIT_CODE=1
fi

if [[ $(grep "^ocredit = -1$" /etc/security/pwquality.conf &>/dev/null ; echo $?) != 0 ]];then
  echo "Password quality is not configured to use at least one special character"
  EXIT_CODE=1
fi


sed -i 's/password    requisite.*/password    requisite     pam_pwquality.so try_first_pass retry=3/g' ./password-auth
sed -i 's/password    requisite.*/password    requisite     pam_pwquality.so try_first_pass retry=3/g' ./system-auth

if [[ $(sha256sum <(grep '^password    requisite.*' /etc/pam.d/system-auth)|cut -d" " -f1) != b6b59de16c42c8081cf752c1171738ae3842604bfde12a3bf5f002b8287ef40c ]];then
  echo 'password policy different from "try_first_pass retry=3", Please check'
  EXIT_CODE=1
fi

if [[ $(sha256sum <(grep '^password    requisite.*' /etc/pam.d/password-auth)|cut -d" " -f1) != b6b59de16c42c8081cf752c1171738ae3842604bfde12a3bf5f002b8287ef40c ]];then
  echo 'password policy different from "try_first_pass retry=3", Please check'
  EXIT_CODE=1
fi

  # Remove old options from password-auth
#sed -i '/^auth        required      pam_faillock.so/d' /etc/pam.d/password-auth
#sed -i '/^auth        [success=1 default=bad] pam_unix.so/d' /etc/pam.d/password-auth
#sed -i '/^auth        [default=die] pam_faillock.so/d' /etc/pam.d/password-auth
#sed -i '/^auth        sufficient    pam_faillock.so/d' /etc/pam.d/password-auth

  # Add new options
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/password-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/password-auth
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/password-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        [success=1 default=bad] pam_unix.so' /etc/pam.d/password-auth
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/password-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/password-auth
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/password-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900' /etc/pam.d/password-auth


  # Remove old options from system-auth
#sed -i '/^auth        required      pam_faillock.so/d' /etc/pam.d/system-auth
#sed -i '/^auth        [success=1 default=bad] pam_unix.so/d' /etc/pam.d/system-auth
#sed -i '/^auth        [default=die] pam_faillock.so/d' /etc/pam.d/system-auth
#sed -i '/^auth        sufficient    pam_faillock.so/d' /etc/pam.d/system-auth

  # Add new options
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/system-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        required      pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/system-auth
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/system-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        [success=1 default=bad] pam_unix.so' /etc/pam.d/system-auth
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/system-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/system-auth
#lastAuthLine=$[$(grep -n ^auth /etc/pam.d/system-auth|cut -d: -f1|tail -1) + 1]
#sed -i '${lastAuthLine}iauth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900' /etc/pam.d/system-auth

#sed -i '/^password    required      pam_pwhistory.so remember=5/d' /etc/pam.d/system-auth
#sed -i '/^password    required      pam_pwhistory.so remember=5/d' /etc/pam.d/password-auth

#lastPasswordLine=$[$(grep -n ^password /etc/pam.d/system-auth) + 1]
#sed -i '${lastPasswordLine}ipassword    required      pam_pwhistory.so remember=5/d' /etc/pam.d/system-auth
#lastPasswordLine=$[$(grep -n ^password /etc/pam.d/password-auth) + 1]
#sed -i '${lastPasswordLine}ipassword    required      pam_pwhistory.so remember=5/d' /etc/pam.d/password-auth



#sed -i '/^password    sufficient    pam_unix.so sha512.*/d' /etc/pam.d/system-auth
#sed -i '/^password    required      pam_pwhistory.so remember=5.*/d' /etc/pam.d/password-auth

#lastPasswordLine=$[$(grep -n ^password /etc/pam.d/system-auth) + 1]
#sed -i '${lastPasswordLine}ipassword    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/d' /etc/pam.d/system-auth
#lastPasswordLine=$[$(grep -n ^password /etc/pam.d/password-auth) + 1]
#sed -i '${lastPasswordLine}ipassword    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/d' /etc/pam.d/password-auth


#sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
#sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
#sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/g' /etc/login.defs
#useradd -D -f 30

#for user in $(cut -d: -f1 /etc/passwd);do
#  chage --maxdays 90 $user
#  chage --mindays 7 $user
#  chage --warndays 8 $user
#  chage --inactive 30 $user
#done

# TODO: Check 'last password change' date, make sure it's not in the past
# chage --list <user> |grep Last

usermod -g 0 root &>/dev/null
if [[ $(grep "^root:" /etc/passwd |cut -d: -f4) != 0 ]];then
  sendLog "root user group id is not 0, Please check"
  EXIT_CODE=1
fi


  ## Umask
for file in {/etc/bashrc,/etc/profile,/etc/profile.d/*.sh};do
  sed -i '/^umask/d' $file
  echo "umask 027" >> $file
done

sed -i '/^auth           required        pam_wheel.so use_uid/d' /etc/pam.d/su
echo 'auth           required        pam_wheel.so use_uid' >> /etc/pam.d/su

  ## Sensitive files permissions
chown root.root /etc/passwd
chmod 644 /etc/passwd

chown root.root /etc/shadow
chmod 600 /etc/shadow

chown root.root /etc/group
chmod 644 /etc/group

chown root.root /etc/gshadow
chmod 000 /etc/gshadow

chown root.root /etc/passwd-
chmod u-x,go-rx /etc/passwd-

chown root.root /etc/shadow-
chmod 000 /etc/shadow-

chown root.root /etc/group-
chmod u-x,go-wx /etc/group-

chown root.root /etc/gshadow-
chmod 000 /etc/gshadow-

# TODO: Add a test

  ## World writable files
if [[ $(find $(df --local -P| tail -n +2 |rev|cut -d" " -f1|rev) -xdev -type f -perm -0002|wc -l) -gt 0 ]];then
  sendLog "There are world writable files on the system, Please check:"
  find $(df --local -P| tail -n +2 |rev|cut -d" " -f1|rev) -xdev -type f -perm -0002
  EXIT_CODE=1
fi
  ## Files and directories without user or group
if [[ $(find $(df --local -P| tail -n +2 |rev|cut -d" " -f1|rev) -xdev -nouser|wc -l) -gt 0 ]];then
  sendLog "There are files or directories without a user owner, Please check:"
  find $(df --local -P| tail -n +2 |rev|cut -d" " -f1|rev) -xdev -nouser
  EXIT_CODE=1
fi

if [[ $(find $(df --local -P| tail -n +2 |rev|cut -d" " -f1|rev) -xdev -nogroup|wc -l) -gt 0 ]];then
  sendLog "There are files or directories without a group owner, Please check:"
  find $(df --local -P| tail -n +2 |rev|cut -d" " -f1|rev) -xdev -nogroup
  EXIT_CODE=1
fi

if [[ $(awk -F: ' ($2 == "") {print $1}' /etc/shadow|wc -l) -gt 0 ]];then
  sendLog "Some users doesn't have a password, Please lock them:"
  awk -F: ' ($2 == "") {print $1}' /etc/shadow
  EXIT_CODE=1
fi

if [[ $(grep '^\+:' /etc/passwd &>/dev/null ; echo $?) == 0 ]];then
  sendLog 'Legacy character "+" is in /etc/passwd, Please check'
  EXIT_CODE=1
fi

if [[ $(grep '^\+:' /etc/shadow &>/dev/null ; echo $?) == 0 ]];then
  sendLog 'Legacy character "+" is in /etc/shadow, Please check'
  EXIT_CODE=1
fi

if [[ $(grep '^\+:' /etc/group &>/dev/null ; echo $?) == 0 ]];then
  sendLog 'Legacy character "+" is in /etc/group, Please check'
  EXIT_CODE=1
fi

if [[ $(awk -F: '($3 == 0) {print $1}' /etc/passwd) != root ]];then
  sendLog "Another user have UID of 0 except root, Please check:"
  awk -F: '($3 == 0) {print $1}' /etc/passwd
  EXIT_CODE=1
fi

  ## Protect root PATH variable
if [[ $(echo $PATH|grep ::) != "" ]];then
  sendLog "Empty directory in PATH, Please check"
  EXIT_CODE=1
fi

if [[ $(echo $PATH|grep :$) != "" ]];then
  sendLog "Trailing : in PATH, Please check"
  EXIT_CODE=1
fi

if [[ $(echo $PATH|grep :\\.:) != "" ]];then
  sendLog "Dot is part of root PATH variable, Please check"
  EXIT_CODE=1
fi

if [[ $(echo $PATH|grep :\\./:) != "" ]];then
  sendLog "Dot is part of root PATH variable, Please check"
  EXIT_CODE=1
fi

if [[ $(find $(echo $PATH|tr ':' ' ') -type d -maxdepth 0 -perm -g=w 2>/dev/null|wc -l) -gt 0 ]];then
  sendLog "Some of the directories in PATH variable are group writable, Please check:"
  find $(echo $PATH|tr ':' ' ') -type d -maxdepth 0 -perm -g=w 2>/dev/null
  EXIT_CODE=1
fi

if [[ $(find $(echo $PATH|tr ':' ' ') -type d -maxdepth 0 -perm -o=w 2>/dev/null|wc -l) -gt 0 ]];then
  sendLog "Some of the directories in PATH variable are world writable, Please check:"
  find $(echo $PATH|tr ':' ' ') -type d -maxdepth 0 -perm -o=w 2>/dev/null
  EXIT_CODE=1
fi

  ## Check home dirs

for user in $(grep -Ev '(root|halt|sync|shutdown|/sbin/nologin|/bin/false)' /etc/passwd |cut -d: -f1,6);do
  if [[ ! -d $(echo $user|cut -d: -f2) ]];then
    sendLog "Home directory of user $(echo $user|cut -d: -f1) does not exists, Please check"
    EXIT_CODE=1
  fi
done

  # Set all home directories to 700
find /home/* -maxdepth 0 -type d -exec chmod 700 {} +
chmod 700 /root

for user in $(grep -Ev '(root|halt|sync|shutdown|/sbin/nologin|/bin/false)' /etc/passwd |cut -d: -f1,6);do
  chown $(echo $user|cut -d: -f1):$(echo $user|cut -d: -f1) $(echo $user|cut -d: -f2)
done

find /home/ -maxdepth 2 -name ".*" -exec chmod go-rwx {} +
find /root/ -maxdepth 1 -name ".*" -exec chmod go-rwx {} +

rm -rf /home/*/.forward
rm -rf /home/*/.netrc
rm -rf /home/*/.rhosts

rm -rf /root/.forward
rm -rf /root/.netrc
rm -rf /root/.rhosts


if [[ $(diff <(cut -d: -f3 /etc/group|sort -un) <(cut -s -d: -f4 /etc/passwd|sort -un) |grep '>'|wc -l) -gt 0 ]];then
  sendLog "There are groups that are in /etc/passwd but not in /etc/group, Please check:"
  diff <(cut -d: -f3 /etc/group|sort -un) <(cut -s -d: -f4 /etc/passwd|sort -un) |grep '>'
  EXIT_CODE=1
fi

if [[ $(cut -d: -f3 /etc/passwd|sort -n|uniq -d |wc -l) -gt 0 ]];then
  sendLog "Duplicate UID in /etc/passwd, Please check"
  EXIT_CODE=1
fi

if [[ $(cut -d: -f3 /etc/group|sort -n|uniq -d |wc -l) -gt 0 ]];then
  sendLog "Duplicate GID in /etc/group, Please check"
  EXIT_CODE=1
fi

if [[ $(cut -d: -f1 /etc/passwd|sort -n|uniq -d|wc -l) -gt 0 ]];then
  sendLog "Duplicate user name in /etc/passwd, Please check"
  EXIT_CODE=1
fi

if [[ $(cut -d: -f1 /etc/group|sort |uniq -d|wc -l) -gt 0 ]];then
  sendLog "Duplicate group name in /etc/group, Please check"
  EXIT_CODE=1
fi


  #*** If using prelink, add $ prelink -ua before running aide --check ***#


  # Installation and configuration of AIDE
#if [[ $(yum -y install aide &>/dev/null ; echo $?) != 0 ]];then
#  echo "Aide failed to install! Please check"
#  EXIT_CODE=1
#fi



  # Running aide --init each time, it doesn't override the last changes (it does not act as aide --update)
  # Running it on background
  # TODO: mv new DB to old DB
#bash -c "aide --init" &

#if [[ $(crontab -l |grep "0 5 * * * /usr/sbin/aide --check &>/dev/null ; echo $?) != 0 ]];then
#  crontab <(crontab -l ; echo "0 5 * * * /usr/sbin/aide --check")
#fi

exit $EXIT_CODE
