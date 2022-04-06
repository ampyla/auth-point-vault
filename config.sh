#!/bin/bash

VSH_VERSION=0.1.4
SSHD_CONFIG_PATH=/etc/ssh/sshd_config
PAMD_CONFIG_PATH=/etc/pam.d/sshd
wget https://releases.hashicorp.com/vault-ssh-helper/${VSH_VERSION}/vault-ssh-helper_${VSH_VERSION}_linux_amd64.zip
unzip vault-ssh-helper_${VSH_VERSION}_linux_amd64.zip
mv vault-ssh-helper /usr/local/bin/
echo success download

mkdir /etc/vault-helper.d/
cat << EOF > /etc/vault-helper.d/config.hcl
vault_addr = "https://vault.service.prod.tech:8200"
ssh_mount_point = "ssh"
tls_skip_verify = true
allowed_roles = "*"
allowed_cidr_list="0.0.0.0/0"
EOF
echo success config vault-helper
sed -i -e 's/^@include common-auth/#@include common-auth/g' ${PAMD_CONFIG_PATH}
echo "auth sufficient pam_exec.so quiet expose_authtok log=/tmp/vaultssh.log /usr/local/bin/vault-ssh-helper -config=/etc/vault-helper.d/config.hcl" | tee -a ${PAMD_CONFIG_PATH}
echo "auth optional pam_unix.so not_set_pass use_first_pass nodelay" | tee -a ${PAMD_CONFIG_PATH}

echo success config PAM
sed -i -e 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' ${SSHD_CONFIG_PATH}
sed -i -e 's/UsePAM no/UsePAM yes/g' ${SSHD_CONFIG_PATH}
sed -i -e 's/PasswordAuthentication yes/PasswordAuthentication yes/g' ${SSHD_CONFIG_PATH}
echo success config SSH
echo 'TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem' >> /etc/ssh/sshd.config
mv /home/demm/trusted-user-ca-keys.pem /etc/ssh/trusted-user-ca-keys.pem
systemctl restart sshd
echo complit
