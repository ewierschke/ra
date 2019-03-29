#!/bin/bash
#
# Description:
#
#
#################################################################
__ScriptName="msi-get-cert-and-password-for-httpd.sh"

log()
{
    logger -i -t "${__ScriptName}" -s -- "$1" 2> /dev/console
    echo "$1"
}  # ----------  end of function log  ----------


die()
{
    [ -n "$1" ] && log "$1"
    log "${__ScriptName} failed"'!'
    exit 1
}  # ----------  end of function die  ----------

usage()
{
    cat << EOT
  Usage:  ${__ScriptName} [options]

  Options:
  -h  Display this message.
  -S  URI of the secret to use to unzip the certificate file.
  -C  URI of the certificate file (zip) to use on httpd.

EOT
}  # ----------  end of function usage  ----------

# Define default values
SECRET_URI=
CERTIFICATE_URI=

# Parse command-line parameters
while getopts :hS:C: opt
do
    case "${opt}" in
        h)
            usage
            exit 0
            ;;
        S)
            SECRET_URI="${OPTARG}"
            ;;
        C)
            CERTIFICATE_URI="${OPTARG}"
            ;;
        \?)
            usage
            echo "ERROR: unknown parameter \"$OPTARG\""
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# ensure epel is enabled
yum -y install epel-release
yum-config-manager --enable epel

# install Azure CLI
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo sh -c 'echo -e "[azure-cli]\nname=Azure CLI\nbaseurl=https://packages.microsoft.com/yumrepos/azure-cli\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/azure-cli.repo'
sudo yum -y install azure-cli jq p7zip

# login
az cloud set --name AzureUSGovernment
az login --identity

if [[ $? -eq 0 ]]
then
    log "Successfully logged in using MSI"
elif [[ $? -ne 0 ]]
then
    die "Failed to login using MSI. Aborting..."
fi

# get secret
secretjson=$(az keyvault secret show --id ${SECRET_URI})
secretvalue=$(jq -r .value <<< $secretjson)

#break up url into parts
urlstring=${CERTIFICATE_URI}
slashseparator="/"
tmp=${urlstring//"$slashseparator"/$'\2'}
IFS=$'\2' read -a arr <<< "$tmp"
hostname=${arr[2]}
containerorsharename=${arr[3]}
filename=${arr[4]}

#find storage service (blob v file) and storage account name
hostnamestring=${hostname}
dotseparator="."
tmp=${hostnamestring//"$dotseparator"/$'\2'}
IFS=$'\2' read -a arr <<< "$tmp"
storageaccountname=${arr[0]}
storageservice=${arr[1]}

if [ $storageservice == blob ]
then 
    # get blob 
    az storage blob download --container-name ${containerorsharename} --file /usr/local/bin/cert.zip --name ${filename}  --account-name ${storageaccountname} --auth-mode login
fi

#unzip blob using secret
cd /usr/local/bin
7za e -p"${secretvalue}" /usr/local/bin/cert.zip 

# adjust /etc/httpd/conf.d/ssl.conf
sed -i.certfilebak "s|SSLCertificateFile.*|SSLCertificateFile /usr/local/bin/cert.crt|g" /etc/httpd/conf.d/ssl.conf
sed -i.keyfilebak "s|SSLCertificateKeyFile.*|SSSLCertificateKeyFile /usr/local/bin/cert.key|g" /etc/httpd/conf.d/ssl.conf

# restart httpd
service httpd restart
