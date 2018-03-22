#!/bin/bash
# Description:
# Trend Micro Deep Security Agent Installer for RHEL/CentOS 7
#
# Trend Micro Deep Security Manager must be configured to allow 
# Agent Initiated Activation
#################################################################
__ScriptName="install-trend-agent.sh"

set -e
set -o pipefail

log()
{
    # Logs messages to logger and stdout
    # Reads log messages from $1 or stdin
    if [[ "${1-UNDEF}" != "UNDEF" ]]
    then
        # Log message is $1
        logger -i -t "${__SCRIPTNAME}" -s -- "$1" 2> /dev/console
        echo "${__SCRIPTNAME}: $1"
    else
        # Log message is stdin
        while IFS= read -r IN
        do
            log "$IN"
        done
    fi
}  # ----------  end of function log  ----------


die()
{
    [ -n "$1" ] && log "$1"
    log "Trend Micro Deep Security Agent install failed"'!'
    exit 1
}  # ----------  end of function die  ----------


retry()
{
    # Make an arbitrary number of attempts to execute an arbitrary command,
    # passing it arbitrary parameters. Convenient for working around
    # intermittent errors (which occur often with poor repo mirrors).
    #
    # Returns the exit code of the command.
    local n=0
    local try=$1
    local cmd="${*: 2}"
    local result=1
    [[ $# -le 1 ]] && {
        echo "Usage $0 <number_of_retry_attempts> <Command>"
        exit $result
    }

    echo "Will try $try time(s) :: $cmd"

    if [[ "${SHELLOPTS}" == *":errexit:"* ]]
    then
        set +e
        local ERREXIT=1
    fi

    until [[ $n -ge $try ]]
    do
        sleep $n
        $cmd
        result=$?
        test $result -eq 0 && break || {
            ((n++))
            echo "Attempt $n, command failed :: $cmd"
        }
    done

    if [[ "${ERREXIT}" == "1" ]]
    then
        set -e
    fi

    return $result
}  # ----------  end of function retry  ----------


usage()
{
    cat << EOT
  Usage:  ${__ScriptName} [options]

  Note:
  If no options are specified, then Guacamole v${__GuacVersion} will be
  installed, but it will not be configured and users will not be able to
  authenticate. Specify -H (and associated options) to configure LDAP
  authentication. Specify -G (and associated options) to configure file-based
  authentication.

  Options:
  -h  Display this message.
  -U  URL from which to download the EL7 Trend Micro Deep Security agent RPM.
  -H  Hostname or IP of the Trend Micro Deep Security Manager server to link to
      (e.g. trend.example.com). Using the FQDN is acceptable as long as it 
      resolves correctly in your environment. 
  -P  Port on which to connect to the Trend Micro Deep Security Manager server. 
      Default is "4120".
  -p  Policy ID with which to associate the new Trend Micro Deep Security agent
EOT
}  # ----------  end of function usage  ----------


# Define default values
RPM_URL=
MGR_HOSTNAME=
PORT="4120"
POLICY_ID=

# Parse command-line parameters
while getopts :hU:H:P:p opt
do
    case "${opt}" in
        h)
            usage
            exit 0
            ;;
        U)
            RPM_URL="${OPTARG}"
            ;;
        H)
            MGR_HOSTNAME="${OPTARG}"
            ;;
        P)
            PORT="${OPTARG}"
            ;;
        p)
            POLICY_ID="${OPTARG}"
            ;;
        \?)
            usage
            echo "ERROR: unknown parameter \"$OPTARG\""
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))


# Validate parameters
if [ -z "${RPM_URL}" ]
then
    die "No RPM_URL (-U) was provided, cannot download agent RPM; exiting"
fi

if [ -z "${MGR_HOSTNAME}" ]
then
    die "No MGR_HOSTNAME (-H) was provided, cannot link to Trend Manager; exiting"
fi

# Check Permissions
if [[ "$EUID" -ne 0 ]]
  then
    log "Must be run as root/sudo"
    exit 1
fi


#Install wget
retry 2 yum -y install wget | log


# Download Agent
# Agent versions need to match the manager, so the RPM_URL should reflect a path
# on the Trend Micro Deep Security Manager
log "Downloading Trend Micro Deep Security Agent RPM"
retry 2 wget ${RPM_URL} -O /root/trendagent.rpm --no-check-certificate --quiet | log


# Install agent rpm
log "Installing Trend Micro Deep Security Agent RPM"
rpm -ihv --replacepkgs /root/trendagent.rpm | log
sleep 5


# Unregister agent from manager
/opt/ds_agent/dsa_control -r | log


# Activating against Trend Micro Deep Security Manager
log "Activating Trend Micro Deep Security Agent to provided Trend Micro Deep Security Manager"
/opt/ds_agent/dsa_control -a dsm://${MGR_HOSTNAME}:${PORT}/ "policyid:${POLICY_ID}" --dsm-retry-interval 10 --max-dsm-retries 3 | log
