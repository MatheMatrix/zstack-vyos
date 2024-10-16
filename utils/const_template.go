package utils

const sshdTemplateArm = `# Auto Create by Zstack, Do Not Modify It
#
# Non-configurable defaults
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTH
LoginGraceTime 120
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Banner /etc/issue.net
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
HostKey /etc/ssh/ssh_host_rsa_key

# Specifies whether sshd should look up the remote host name,
# and to check that the resolved host name for the remote IP
# address maps back to the very same IP address.
UseDNS yes

# Specifies the port number and local addresses that sshd listens on.  The default port is 22.
# Port 22
ListenAddress {{.ListenAddress}}:{{.Port}}

# Gives the verbosity level that is used when logging messages from sshd
LogLevel INFO

# Specifies whether root can log in using ssh
PermitRootLogin no

# Specifies whether password authentication is allowed
PasswordAuthentication no`

const sshdTemplate = `# Auto Create by Zstack, Do Not Modify It
#

#Port 22
ListenAddress {{.ListenAddress}}:{{.Port}}
Protocol 2
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 768

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin no
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile     %h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
PasswordAuthentication no

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

UsePAM yes
# HostKey for protocol version 1
HostKey /etc/ssh/ssh_host_key
UseDNS yes`
