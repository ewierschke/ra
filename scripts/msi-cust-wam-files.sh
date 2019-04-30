#!/bin/bash
#
# Description:
#
#
#################################################################
__ScriptName="msi-cust-wam-files.sh"

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
  -S  URI of the custom salt-content.zip file to use with watchmaker.
  -C  URI of the custom config.yaml file to use with watchmaker.

EOT
}  # ----------  end of function usage  ----------

# Define default values
SALT_CONTENT_URI=
CONFIG_YAML_URI=

# Parse command-line parameters
while getopts :hS:C: opt
do
    case "${opt}" in
        h)
            usage
            exit 0
            ;;
        S)
            SALT_CONTENT_URI="${OPTARG}"
            ;;
        C)
            CONFIG_YAML_URI="${OPTARG}"
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
sudo yum -y install azure-cli 

# determine environment for az login from instance metadata service
sudo yum -y install jq
apiversions=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance")
firstapiversion=$(jq '.["newest-versions"][0]' <<< $apiversions)
firstapiversionnoquotes=$(sed -e 's/^"//' -e 's/"$//' <<<"$firstapiversion")
metadata=$(curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=${firstapiversionnoquotes}")
environment=$(jq .compute.azEnvironment <<< $metadata)
environmentnoquotes=$(sed -e 's/^"//' -e 's/"$//' <<<"$environment")
#set az cloud set name parameter value
if [[ $environmentnoquotes == "AzurePublicCloud" ]]
then
    azloginenvname=AzureCloud
elif [[ $environmentnoquotes == "AzureUSGovernmentCloud" ]]
then
    azloginenvname=AzureUSGovernment
fi

# login
az cloud set --name $azloginenvname
az login --identity
if [[ $? -eq 0 ]]
then
    log "Successfully logged in using MSI"
elif [[ $? -ne 0 ]]
then
    die "Failed to login using MSI. Aborting..."
fi

### SALT CONTENT ###
#break up salt content url into parts
urlstring=${SALT_CONTENT_URI}
slashseparator="/"
tmp=${urlstring//"$slashseparator"/$'\2'}
IFS=$'\2' read -a arr <<< "$tmp"
hostname=${arr[2]}
containerorsharename=${arr[3]}
filename=${arr[4]}

#find salt content url storage service (blob v file) and storage account name
hostnamestring=${hostname}
dotseparator="."
tmp=${hostnamestring//"$dotseparator"/$'\2'}
IFS=$'\2' read -a arr <<< "$tmp"
storageaccountname=${arr[0]}
storageservice=${arr[1]}

if [ $storageservice == blob ]
then 
    # get blob 
    # be sure Managed Identity has been granted Storage Blob Data Reader IAM Role to storage account
    az storage blob download --container-name ${containerorsharename} --file "/var/www/html/salt-content.zip" --name ${filename}  --account-name ${storageaccountname} --auth-mode login
elif [ $storageservice == file ]
then
    # get file
    # be sure Managed Identity has been granted Reader and Storage Account Key Operator Service Role IAM Roles to storage account
    az storage file download --path ${filename} --share-name ${containerorsharename} --dest "/var/www/html/salt-content.zip" --account-name ${storageaccountname}
fi
### END SALT CONTENT ###

### CONFIG YAML CONTENT ###
#break up salt content url into parts
urlstring=${CONFIG_YAML_URI}
slashseparator="/"
tmp=${urlstring//"$slashseparator"/$'\2'}
IFS=$'\2' read -a arr <<< "$tmp"
hostname=${arr[2]}
containerorsharename=${arr[3]}
filename=${arr[4]}

#find salt content url storage service (blob v file) and storage account name
hostnamestring=${hostname}
dotseparator="."
tmp=${hostnamestring//"$dotseparator"/$'\2'}
IFS=$'\2' read -a arr <<< "$tmp"
storageaccountname=${arr[0]}
storageservice=${arr[1]}

if [ $storageservice == blob ]
then 
    # get blob 
    # be sure Managed Identity has been granted Storage Blob Data Reader IAM Role to storage account
    az storage blob download --container-name ${containerorsharename} --file "/root/config.yaml" --name ${filename}  --account-name ${storageaccountname} --auth-mode login
elif [ $storageservice == file ]
then
    # get file
    # be sure Managed Identity has been granted Reader and Storage Account Key Operator Service Role IAM Roles to storage account
    az storage file download --path ${filename} --share-name ${containerorsharename} --dest "/root/config.yaml" --account-name ${storageaccountname}
fi
### END CONFIG YAML CONTENT ###