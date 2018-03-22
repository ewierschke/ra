#!/bin/bash
# Description:
# Nessus Agent Installer for RHEL/CentOS 7
#
#################################################################
__ScriptName="install-nessus-agent.sh"

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
    log "Nessus Agent install failed"'!'
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
  -U  URL from which to download the EL7 Nessus agent RPM.
  -H  Hostname or IP of the Nessus Manager server to link to
      (e.g. nessus.example.com). Using the FQDN is acceptable as long as it 
      resolves correctly in your environment. 
  -P  Port on which to connect to the Nessus Manager server. Default is "8834".
  -K  Agent Key for the manager to which you are attempting to link this agent
  -G  Existing Agent Group(s) that you want your Agent to be a member of.
  -N  A name for your Agent.  Default uses the instance hostname.
EOT
}  # ----------  end of function usage  ----------


# Define default values
RPM_URL=
MGR_HOSTNAME=
PORT="8834"
AGENT_KEY=
NESSUS_GROUPS=
AGENT_NAME="$(hostname)"

# Parse command-line parameters
while getopts :hU:H:P:K:G:N opt
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
        K)
            AGENT_KEY="${OPTARG}"
            ;;
        G)
            NESSUS_GROUPS="${OPTARG}"
            ;;
        N)
            AGENT_NAME="${OPTARG}"
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
    die "No MGR_HOSTNAME (-H) was provided, cannot link to Nessus Manager; exiting"
fi

if [ -z "${AGENT_KEY}" ]
then
    die "No AGENT_KEY (-K) was provided, cannot link  to Nessus Manager; exiting"
fi

if [ -n "${NESSUS_GROUPS}" ]
then 
    QUOTED_GROUPS=\"${NESSUS_GROUPS}\"
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
# Unable to automatically fetch agent from vendor because of license acceptance 
# requirement
# Agent installers are available at https://www.tenable.com/agent-download
log "Downloading Nessus Agent RPM"
retry 2 wget -O /root/nessusagent.rpm "${RPM_URL}" | log


# Install agent rpm
log "Installing Nessus Agent RPM"
rpm -ihv --replacepkgs /root/nessusagent.rpm | log
sleep 5


# Link to Nessus Manager
log "Linking Nessus Agent to provided Nessus Manager"
/opt/nessus_agent/sbin/nessuscli agent link --key=${AGENT_KEY} --name=${AGENT_NAME} --groups=${QUOTED_GROUPS} --host=${MGR_HOSTNAME} --port=${PORT} | log


# Start Agent service
log "Starting Nessus Agent"
/bin/systemctl start nessusagent.service | log
