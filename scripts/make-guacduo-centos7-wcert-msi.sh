#!/bin/bash
#
# Description:
#    This script is intended to aid an administrator in quickly
#    setting up a baseline configuration of the Guacamole
#    management-protocol HTTP-tunneling service. When the script
#    exits successfully:
#    * The Tomcat servlet-service will have been downloaded and
#      enabled
#    * N/A-The Guacamole service will have been configured to tunnel
#      SSH based connections to the Guacamole host to a remote,
#      HTML 5 compliant web browser.
#    * N/A-Apache 2.4 will have been configured to provide a proxy of
#      all public-facing port 80/tcp traffic to the Guacamole
#      servlet listening at localhost port 8080/tcp
#    * Feb-2017 - modified to run script under CentOS6 after running 
#      SystemPrep hardening script
#    * Script relies on preparation of LDAP Schema and object creation
#      for connection configuration
#
#################################################################
__ScriptName="make-guacduo-centos7-wcert-msi.sh"
__GuacVersion="1.0.0"

log()
{
    logger -i -t "${__ScriptName}" -s -- "$1" 2> /dev/console
    echo "$1"
}  # ----------  end of function log  ----------


die()
{
    [ -n "$1" ] && log "$1"
    log "Guacamole install failed"'!'
    exit 1
}  # ----------  end of function die  ----------


__md5sum()
{
    local pass="${1}"
    echo -n "${pass}" | /usr/bin/md5sum - | cut -d ' ' -f 1
}  # ----------  end of function md5sum  ----------


retry()
{
    local n=0
    local try=$1
    local cmd="${@: 2}"
    [[ $# -le 1 ]] && {
    echo "Usage $0 <number_of_retry_attempts> <Command>"; }

    until [[ $n -ge $try ]]
    do
        $cmd && break || {
            echo "Command Fail.."
            ((n++))
            echo "retry $n ::"
            sleep $n;
            }
    done
}  # ----------  end of function retry  ----------


usage()
{
    cat << EOT
  Usage:  ${__ScriptName} [options]

  Note:
  If no options are specified, then Guacamole ${__GuacVersion} will be
  installed, but it will not be configured and users will not be able to
  authenticate. Specify -H (and associated options) to configure LDAP
  authentication. Specify -G (and associated options) to configure file-based
  authentication.

  Options:
  -h  Display this message.
  -H  Hostname of the LDAP server to authenticate users against
      (e.g. ldap.example.com). Using the domain DNS name is acceptable as long
      as it resolves to an LDAP server (e.g. example.com). If specified, LDAP
      authentication will be installed and configured. Requires -D.
  -D  Distinguished Name (DN) of the directory (e.g. DN=example,DN=com).
      Required by -H.
  -U  The base of the DN for all Guacamole users. This is prepended to the
      directory DN (-D) to create the full DN to the user container. This will
      be appended to the username when a user logs in. Default is "CN=Users".
  -R  The base of the DN for all Guacamole roles. This is used by the LDAP
      plugin to search for groups the user is a member of. Using this option
      will enable Roles Based Access Control (RBAC) support. This is prepended
      to the directory DN (-D) to create the full DN to the RBAC container.
  -A  The attribute which contains the username and which is part of the DN
      for all Guacamole users. Usually, this will be "uid" or "cn". This is
      used together with the user base DN (-U) to derive the full DN of each
      user logging in. Default is "cn".
  -C  The base of the DN for all Guacamole configurations. Each configuration
      is analogous to a connection. This is prepended to the directory DN (-D)
      to create the full DN to the configuration container. Default is
      "CN=GuacConfigGroups". NOTE: This default value does not exist by
      default in the LDAP directory and will need to be created, or a
      different value will need to be provided.
  -P  Port on which to connect to the LDAP server. Default is "389".
  -v  Version of Guacamole to build, install, and configure.
      Default is "${__GuacVersion}".
  -G  A username authorized to use the Guacamole service that will be
      authenticated using the basic file authentication provider.
  -g  Password for the Guacamole user (-G). If -G is provided, then this
      parameter is required.
  -S  An Operating System (OS) username that will be created and allowed to
      login via SSH. This parameter is only valid if -G is specified, as well.
      If this parameter is not provided but -G is, then the -G username will
      be used for the OS user.
  -s  Password for the OS user (-S). If -S is specified, then this parameter
      is required.
  -L  URL for first link to be included in Guac login page. If -T is specified,
      then this parameter is required for successful modification.
  -T  Text to be displayed for the URL provided with -L.  If -L is specified,
      then this parameter is required for successful modification.
  -l  URL for second link to be included in Guac login page. If -t is specified,
      then this parameter is required for successful modification.
  -t  Text to be displayed for the URL provided with -l.  If -l is specified,
      then this parameter is required for successful modification.
  -d  API Hostname to be used for Duo integration.
  -I  Integration key provided by Duo for use in configuring Duo extension.  
  -i  Secret key provided by Duo for use in configuring Duo extension.  Value must
      be exactly 20 characters.
  -K  Application key required for configuration of Duo extension.  Value must be
      at least 40 characters.  If -d is specified but -K is not, a random application
      key will be generated for you.
  -c  URL from which to download untrusted LDAP server public certificate
      to be added to tomcat cacerts store for LDAPS connection.
  -B  Text for branding of the homepage. Default is "Apache Guacamole".
  -b  Write out /etc/issue contents as legal banner on logon page (yes if parameter selected)
  -o  URL from which to download PNG image to be used for logo.
  -M  VM is configured with MSI to access urls
  -E  URL from which to download SSL certificate zip file.
  -F  URI to Azure Key Vault secret value used to open SSL certificate zip file. 
EOT
}  # ----------  end of function usage  ----------


#Guac manifest file for using extensions
write_manifest()
{
    log "Writing Guac manifest file"
    (
        printf "{\n"
        printf "\"guacamoleVersion\" : \"$GUAC_VERSION\",\n"
        printf "\"name\" : \"Custom Extension\",\n"
        printf "\"namespace\" : \"custom-extension\",\n"
        printf "\"css\" : [ \"css/logo-override.css\" ],\n"
        printf "\"html\" : [ \"custom-urls.html\" ],\n"
        printf "\"translations\" : [ \"translations/en.json\" ],\n"
        printf "\"resources\" : {\n"
        printf "    \"images/custom-logo.png\" : \"image/png\"\n"
        printf "}\n"
        printf "}\n"
    ) > /etc/guacamole/extensions/guac-manifest.json
    zero=0
    #if ! ( [[ -n "${URL_1}" ]] || [[ -n "${URL_2}" ]] || [[ "${BANNER}" == "${zero}" ]] )
    #then
    #    sed -i '/html/d' /etc/guacamole/extensions/guac-manifest.json
    #fi
    mkdir -p /etc/guacamole/extensions/css
    log "Writing placeholder custom css for custom Guac extension pointing to standard guac logo"
    (
        printf ".login-ui .login-dialog .logo {\n"
        printf "    background-image: url('images/guac-tricolor.png');\n"
        printf "}\n"
    ) > /etc/guacamole/extensions/css/logo-override.css
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" "guac-manifest.json"
    zip -u "custom.jar" "css/logo-override.css"
}  # ----------  end of function write_manifest  ----------


#Guac links extension file
write_links()
{
    log "Writing Guac html extension file to add in custom URLs"
    (
        printf "<meta name=\"after\" content=\".login-ui .login-dialog\">\n"
        printf "\n"
        printf "<div class=\"welcome\">\n"
        printf "<p>\n"
        printf "<a target=\"_blank\" href=\"${URL_1}\">${URLTEXT_1}</a>\n"
        printf "</p>\n"
        printf "<p>\n"
        printf "<a target=\"_blank\" href=\"${URL_2}\">${URLTEXT_2}</a>\n"
        printf "</p>\n"
        printf "</div>\n"
    ) >> /etc/guacamole/extensions/custom-urls.html
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" "custom-urls.html"
    #cp /etc/guacamole/extensions/custom.jar /usr/share/tomcat/.guacamole/extensions/
    log "Successfully added URL(s) to Guacamole login page"
}  # ----------  end of function write_links  ----------


#Guac branding extension file
write_brand()
{
    log "Writing Guac translations extension file to add in custom branding text"
    mkdir -p /etc/guacamole/extensions/translations
    (
        printf "{\n"
        printf "\"APP\" : { \"NAME\" : \"${BRANDTEXT}\" }\n"
        printf "}\n"
    ) > /etc/guacamole/extensions/translations/en.json
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" "translations/en.json"
    log "Successfully added branding text to Guacamole login page"
}  # ----------  end of function write_brand  ----------


#Guac legal banner/notice html extension file
write_legal()
{
    log "Writing Guac legal notice html extension file to add in custom URLs"
    readarray issuecontent < /etc/issue
    kernel="Kernel"
    word=$(echo ${issuecontent[1]} | awk '{print $1}')
    if [[ "${kernel}" == "${word}" ]] 
    then 
        echo -n "" > /etc/guacamole/extensions/issue
    else
        cp /etc/issue /etc/guacamole/extensions/issue
    fi
    sed -i 's/\r//g' /etc/guacamole/extensions/issue
    sed -i ':a;N;$!ba;s/\n//g' /etc/guacamole/extensions/issue
    sed -i 's|\: |\:<br /><br />|g' /etc/guacamole/extensions/issue
    sed -i 's|\. |\.<br /><br />|g' /etc/guacamole/extensions/issue && sed -i 's|\.<br /><br />|\. |1' /etc/guacamole/extensions/issue && sed -i 's|\.<br /><br />|\. |6' /etc/guacamole/extensions/issue
    ISSUE=$(cat /etc/guacamole/extensions/issue)
    (
        printf "<meta name=\"after\" content=\".login-ui .login-dialog\">\n"
        printf "\n"
        printf "<div style=\"width:6in; margin:0 auto; class=\"welcome\">\n"
        printf "<p>\n"
        printf "${ISSUE}\n"
        printf "</p>\n"
        printf "</div>\n"
    ) >> /etc/guacamole/extensions/custom-urls.html
    cd "/etc/guacamole/extensions"
    zip -u "custom.jar" "custom-urls.html"
    log "Successfully added legal notice to Guacamole login page"
}  # ----------  end of function write_legal  ----------


#Replace Guac logo in extension file
write_logo()
{
    log "Update custom extension to replace Guac logo"
    yum -y install ImageMagick
    mkdir -p /etc/guacamole/extensions/images
    log "Downloading logo file"
    retry 5 wget --timeout=10 \
    "${LOGO_URL}" -O /etc/guacamole/extensions/images/custom-logo.png || \
    die "Could not download logo file"
    imagetype=$(identify /etc/guacamole/extensions/images/custom-logo.png | awk '{print $2}')
    pngcheck=PNG
    cd "/etc/guacamole/extensions"
    if [[ "${pngcheck}" == "${imagetype}" ]] 
    then 
        log "Overwriting custom css for Guac custom extension file"
        (
            printf ".login-ui .login-dialog .logo {\n"
            printf "    background-image: url('app/ext/custom-extension/images/custom-logo.png');\n"
            printf "}\n"
        ) > /etc/guacamole/extensions/css/logo-override.css
        zip -u "custom.jar" "images/custom-logo.png"
        zip -u "custom.jar" "css/logo-override.css"
        log "Successfully added logo image to custom extension"
    else
        log "Invalid PNG image passed to parameter, not changing logo"
    fi
}  # ----------  end of function write_logo  ----------


# Define default values
LDAP_HOSTNAME=
LDAP_DOMAIN_DN=
LDAP_USER_BASE="CN=Users"
LDAP_USER_ATTRIBUTE="cn"
LDAP_CONFIG_BASE="CN=GuacConfigGroups"
LDAP_GROUP_BASE="CN=Users"
LDAP_PORT="389"
GUAC_VERSION="${__GuacVersion}"
GUAC_USERNAME=
GUAC_PASSWORD=
SSH_USERNAME=
SSH_PASSWORD=
URL_1=
URLTEXT_1=
URL_2=
URLTEXT_2=
DUO_API_HOSTNAME=
DUO_INTKEY=
DUO_SECRET=
DUO_APPKEY=
LDAP_CERT=
BRANDTEXT=
BANNER=0
LOGO_URL=
USE_MSI=0
CERTIFICATE_ZIP_URL=
CERTIFICATE_KV_SECRET_URI=

# Parse command-line parameters
while getopts :hH:D:U:R:A:C:P:v:G:g:S:s:L:T:l:t:d:I:i:K:c:B:o:ME:F:b opt
do
    case "${opt}" in
        h)
            usage
            exit 0
            ;;
        H)
            LDAP_HOSTNAME="${OPTARG}"
            ;;
        D)
            LDAP_DOMAIN_DN="${OPTARG}"
            ;;
        U)
            LDAP_USER_BASE="${OPTARG}"
            ;;
        R)
            LDAP_GROUP_BASE="${OPTARG}"
            ;;
        A)
            LDAP_USER_ATTRIBUTE="${OPTARG}"
            ;;
        C)
            LDAP_CONFIG_BASE="${OPTARG}"
            ;;
        P)
            LDAP_PORT="${OPTARG}"
            ;;
        v)
            GUAC_VERSION="${OPTARG}"
            ;;
        G)
            GUAC_USERNAME="${OPTARG}"
            ;;
        g)
            GUAC_PASSWORD="${OPTARG}"
            ;;
        S)
            SSH_USERNAME="${OPTARG}"
            ;;
        s)
            SSH_PASSWORD="${OPTARG}"
            ;;
        L)
            URL_1="${OPTARG}"
            ;;
        T)
            URLTEXT_1="${OPTARG}"
            ;;
        l)
            URL_2="${OPTARG}"
            ;;
        t)
            URLTEXT_2="${OPTARG}"
            ;;
        d)
            DUO_API_HOSTNAME="${OPTARG}"
            ;;
        I)
            DUO_INTKEY="${OPTARG}"
            ;;
        i)
            DUO_SECRET="${OPTARG}"
            ;;
        K)
            DUO_APPKEY="${OPTARG}"
            ;;
        c)
            LDAP_CERT="${OPTARG}"
            ;;
        B)
            BRANDTEXT="${OPTARG}"
            ;;
        b)
            BANNER=1
            ;;
        o)
            LOGO_URL="${OPTARG}"
            ;;
        M)
            USE_MSI=1
            ;;
        E)
            CERTIFICATE_ZIP_URL="${OPTARG}"
            ;;
        F)
            CERTIFICATE_KV_SECRET_URI="${OPTARG}"
            ;;
        \?)
            usage
            echo "ERROR: unknown parameter \"$OPTARG\""
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

log "Clean yum cache"
retry 5 yum clean all

log "Installing EPEL repo"
retry 2 yum -y install epel-release
# Validate parameters
if [ -n "${LDAP_HOSTNAME}" ]
then
    if [ -z "${LDAP_DOMAIN_DN}" ]
    then
        die "LDAP Hostname was provided (-H), but the LDAP Domain DN was not (-D)"
    fi
elif [ -n "${LDAP_DOMAIN_DN}" ]
then
    die "LDAP Domain DN was provided (-D), but the LDAP Hostname was not (-H)"
fi

if [ -n "${GUAC_USERNAME}" ]
then
    if [ -z "${GUAC_PASSWORD}" ]
    then
        die "Guacamole username was provided (-G), but the password was not (-s)"
    fi
    if [ -z "${SSH_USERNAME}" ]
    then
        SSH_USERNAME="${GUAC_USERNAME}"
        SSH_PASSWORD="${GUAC_PASSWORD}"
    fi
fi


# Validate parameter pairs of URL and URLTEXT are appropriately populated
if [ -n "${URL_1}" ]
then
    if [ -z "${URLTEXT_1}" ]
    then
        die "URL1 was provided (-L), but the partner URLTEXT was not (-T), login page unmodified; exiting"
    fi
elif [ -n "${URLTEXT_1}" ]
then
    die "URLTEXT1 was provided (-T), but the URL was not (-L), login page unmodified; exiting"
fi

if [ -n "${URL_2}" ]
then
    if [ -z "${URLTEXT_2}" ]
    then
        die "URL2 was provided (-l), but the partner URLTEXT was not (-t), login page unmodified; exiting"
    fi
elif [ -n "${URLTEXT_2}" ]
then
    die "URLTEXT2 was provided (-t), but the URL was not (-l), login page unmodified; exiting"
fi

# Validate DUO parameters
if [ -n "${DUO_API_HOSTNAME}" ]
then
    if [ -z "${DUO_INTKEY}" ] 
    then
        die "DUO API Hostname was provided (-d), but the DUO Integration Key was not (-I)"
    fi
elif [ -n "${DUO_SECRET}" ]
then
    die "DUO API Hostname was provided (-d), but the DUO Secret Key was not (-i)"
fi

# Check for DUO_APPKEY parameter
if [ -n "${DUO_API_HOSTNAME}" ]
then
    if [ -z "${DUO_APPKEY}" ]
    then
        log "DUO API Hostname was provided (-d), but an application key was (-K), assuming new/standalone instance"
        yum -y install pwgen
        DUO_APPKEY="$(pwgen 40 1)" 
    fi
fi


# Set internal variables
PWCRYPT=$( python -c "import random,string,crypt,getpass,pwd; \
           randomsalt = ''.join(random.sample(string.ascii_letters,8)); \
           print crypt.crypt('${SSH_PASSWORD}', '\$6\$%s))\$' % randomsalt)" )
GUACPASS_MD5=$(__md5sum "${GUAC_PASSWORD}")
GUAC_SOURCE="https://archive.apache.org/dist/guacamole/"${GUAC_VERSION}"/source/"
GUAC_BINARY="https://archive.apache.org/dist/guacamole/"${GUAC_VERSION}"/binary/"
GUAC_EXTENSIONS="https://archive.apache.org/dist/guacamole/"${GUAC_VERSION}"/binary/"
FREERDP_REPO="https://github.com/FreeRDP/FreeRDP"
FREERDP_BRANCH="stable-1.1"
ADDUSER="/usr/sbin/useradd"
MODUSER="/usr/sbin/usermod"


# Start the real work
log "Installing common tools"
retry 5 yum -y install yum-utils yum-plugin-fastestmirror wget ntp zip

log "Installing OS standard Tomcat"
retry 5 yum -y install tomcat || die "Failed to install tomcat"

log "Installing utils and libraries to build freerdp from source"
retry 5 yum -y install git gcc cmake openssl-devel libX11-devel libXext-devel \
    libXinerama-devel libXcursor-devel libXi-devel libXdamage-devel \
    libXv-devel libxkbfile-devel alsa-lib-devel cups-devel ffmpeg-devel \
    glib2-devel \
    || die "Failed to install packages required to build freerdp"

# Build freerdp
cd /root
FREERDP_BASE=$(basename ${FREERDP_REPO} .git)
rm -rf "${FREERDP_BASE}"
retry 5 git clone "${FREERDP_REPO}" || \
    die "Could not clone ${FREERDP_REPO}"
cd "${FREERDP_BASE}"
git checkout "${FREERDP_BRANCH}" || \
    die "Could not checkout branch ${FREERDP_BRANCH}"
log "Building ${FREERDP_BASE} from source"
cmake -DCMAKE_BUILD_TYPE=Debug -DWITH_SSE2=ON -DWITH_DEBUG_ALL=ON .
make
make install
(
    printf "/usr/local/lib/freerdp\n"
    printf "/usr/local/lib64/freerdp\n"
    printf "/usr/local/lib\n"
    printf "/usr/local/lib64\n"
) > /etc/ld.so.conf.d/freerdp.conf
ldconfig


log "Installing libraries to build guacamole from source"
retry 5 yum -y install gcc cairo-devel libjpeg-turbo-devel libjpeg-devel libpng-devel \
    uuid-devel pango-devel libssh2-devel pulseaudio-libs-devel openssl-devel \
    libvorbis-devel dejavu-sans-mono-fonts libwebp-devel log4j \

# Build guacamole-server
cd /root
GUAC_FILEBASE="guacamole-server-${GUAC_VERSION}"
rm -rf "${GUAC_FILEBASE}"
log "Downloading and extracting ${GUAC_FILEBASE}.tar.gz"
retry 5 wget --timeout=10 "${GUAC_SOURCE}/${GUAC_FILEBASE}.tar.gz" -O "${GUAC_FILEBASE}.tar.gz" || \
    die "Could not download ${GUAC_FILEBASE}.tar.gz"
tar -xvf "${GUAC_FILEBASE}.tar.gz" || \
    die "Could not extract ${GUAC_FILEBASE}.tar.gz"
cd "${GUAC_FILEBASE}"
log "Building ${GUAC_FILEBASE} from source"
./configure --with-init-dir=/etc/init.d
make
make install
ldconfig


# Create guacamole directories as necessary
for GUAC_DIR in "/etc/guacamole" "/etc/guacamole/extensions" "/etc/guacamole/lib"
do
    if [[ ! -d "${GUAC_DIR}" ]]
    then
        log "Creating ${GUAC_DIR} directory"
        if [[ $(mkdir -p "${GUAC_DIR}")$? -ne 0 ]]
        then
            die "Cannot populate ${GUAC_DIR}"
        fi
    fi
done
# Set guacamole directories perms
for GUAC_DIR in "/etc/guacamole" "/etc/guacamole/extensions" "/etc/guacamole/lib"
do
    if [[ ! -d "${GUAC_DIR}" ]]
    then
        log "setting perms on ${GUAC_DIR} directory"
        if [[ $(chmod 755 "${GUAC_DIR}")$? -ne 0 ]]
        then
            die "Cannot set perms on ${GUAC_DIR}"
        fi
    fi
done


# Install the Guacamole client
log "Downloading Guacamole client from project repo"
cd /root
retry 5 wget --timeout=10 "${GUAC_BINARY}/guacamole-${GUAC_VERSION}.war" -O "guacamole-${GUAC_VERSION}.war" || \
    die "Could not download ${GUAC_BINARY}"
mv "guacamole-${GUAC_VERSION}.war" /var/lib/tomcat/webapps/ROOT.war || \
    die "Could not move ${GUAC_BINARY}"
chown tomcat:tomcat /var/lib/tomcat/webapps/ROOT.war || \
    die "Could not chown to tomcat user ${GUAC_BINARY}"

# Gotta make SELinux happy...
if [[ $(getenforce) = "Enforcing" ]] || [[ $(getenforce) = "Permissive" ]]
then
    chcon -R --reference=/var/lib/tomcat/webapps \
        /var/lib/tomcat/webapps/ROOT.war
    if [[ $(getsebool httpd_can_network_relay | \
        cut -d ">" -f 2 | sed 's/[ ]*//g') = "off" ]]
    then
        log "Enabling httpd-based proxying within SELinux"
        setsebool -P httpd_can_network_relay=1
    fi
fi


# Configure Guacamole
# Create basic config files in /etc/guacamole
cd /etc/guacamole
log "Writing /etc/guacamole/guacamole.properties"
(
    echo "# Hostname and port of guacamole proxy"
    echo "guacd-hostname:      localhost"
    echo "guacd-port:          4822"
    echo "api-session-timeout: 15"
) > /etc/guacamole/guacamole.properties
# Set guacamole.properties file perms
chmod 644 /etc/guacamole/guacamole.properties
log "Writing /etc/guacamole/logback.xml"
(
    printf "<configuration>\n"
    printf "\n"
    printf "\t<!-- Appender for debugging -->\n"
    printf "\t<appender name=\"GUAC-DEBUG\" class=\"ch.qos.logback.core.FileAppender\">\n"
    printf "\t\t<file>/var/log/tomcat/guacamole.log</file>\n"
    printf "\t\t<encoder>\n"
    printf "\t\t\t<pattern>%%d{yyyy-MM-dd HH:mm:ss} [%%thread] %%-5level %%logger{36} - %%msg%%n</pattern>\n"
    printf "\t\t</encoder>\n"
    printf "\t</appender>\n"
    printf "\n"
    printf "\t<!-- Log at DEBUG level -->\n"
    printf "\t<root level=\"debug\">\n"
    printf "\t\t<appender-ref ref=\"GUAC-DEBUG\"/>\n"
    printf "\t</root>\n"
    printf "\n"
    printf "</configuration>\n"
) > /etc/guacamole/logback.xml
# Set logback file perms
chmod 644 /etc/guacamole/logback.xml
log "Writing /etc/guacamole/guacd.conf"
(
    printf "# guacd configuration file\n\n"
    printf "[daemon]\n"
    printf "log_level = debug\n"
) > /etc/guacamole/guacd.conf
# Set guacd file perms
chmod 644 /etc/guacamole/guacd.conf
log "Writing /etc/rsyslog.d/00-guacd.conf"
(
    printf "# Log guacd generated log messages to file\n"
    printf ":syslogtag, startswith, \"guacd\" /var/log/guacd.log\n\n"
    printf "# comment out the following line to allow GUACD messages through.\n"
    printf "# Doing so means you'll also get GUACD messages in /var/log/syslog\n"
    printf "& ~\n"
) > /etc/rsyslog.d/00-guacd.conf
# Set 00-guacd.conf file perms
chmod 644 /etc/rsyslog.d/00-guacd.conf

if [ -n "${GUAC_USERNAME}" ]
then
    log "Create the SSH login-user [${SSH_USERNAME}"
    getent passwd ${SSH_USERNAME} > /dev/null
    if [[ $? -eq 0 ]]
    then
        log "User account already exists [${SSH_USERNAME}]."
    elif [[ $(${ADDUSER} ${SSH_USERNAME})$? -ne 0 ]]
    then
        die "Failed to create ssh user account [${SSH_USERNAME}]. Aborting..."
    fi

    log "Set the password for the SSH login-user"
    if  [[ $(${MODUSER} -p "${PWCRYPT}" ${SSH_USERNAME}) -ne 0 ]]
    then
        die "Failed to set password for ssh user account. Aborting..."
    fi

    log "Adding the SSH login-user to sudoers list"
    printf "${SSH_USERNAME}\tALL=(root)\tNOPASSWD:ALL\n" > \
        /etc/sudoers.d/user_${SSH_USERNAME}
    if [[ $? -ne 0 ]]
    then
        die "Failed to add ${SSH_USERNAME} to sudoers."
    fi

    log "Adding the basic user mapping setting to guacamole.properties"
    (
        echo ""
        echo "# Properties used by BasicFileAuthenticationProvider"
        echo "basic-user-mapping: /etc/guacamole/user-mapping.xml"
    ) >> /etc/guacamole/guacamole.properties

    log "Writing /etc/guacamole/user-mapping.xml"
    (
        printf "<user-mapping>\n"
        printf "\t<!-- Per-user authentication and config information -->\n"
        printf "\t<authorize username=\"%s\" password=\"%s\" encoding=\"%s\">\n" "${GUAC_USERNAME}" "${GUACPASS_MD5}" "md5"
        printf "\t\t<protocol>ssh</protocol>\n"
        printf "\t\t\t<param name=\"hostname\">localhost</param>\n"
        printf "\t\t\t<param name=\"port\">22</param>\n"
        printf "\t\t\t<param name=\"font-name\">DejaVu Sans Mono</param>\n"
        printf "\t\t\t<param name=\"font-size\">10</param>\n"
        printf "\t</authorize>\n"
        printf "</user-mapping>\n"
    ) > /etc/guacamole/user-mapping.xml
fi

if [ -n "${LDAP_HOSTNAME}" ]
then
    # Install the Guacamole LDAP auth extension
    log "Downloading Guacmole ldap extension"
    GUAC_LDAP="guacamole-auth-ldap-${GUAC_VERSION}"
    cd /root
    retry 5 wget --timeout=10 \
        "${GUAC_EXTENSIONS}/${GUAC_LDAP}.tar.gz" -O "${GUAC_LDAP}.tar.gz" || \
        die "Could not download ldap extension"

    log "Extracting Guacamole ldap extension"
    cd /root
    tar -xvf "${GUAC_LDAP}.tar.gz" || \
        die "Could not extract Guacamole ldap plugin"

    log "Installing Guacamole ldap .jar file in the extensions directory"
    cp "${GUAC_LDAP}/${GUAC_LDAP}.jar" "/etc/guacamole/extensions"
    chmod 644 "/etc/guacamole/extensions/""${GUAC_LDAP}.jar"

    #Configure guacamole.properties file for appropriate LDAP port number
    if [[ ${LDAP_PORT} -eq 389 ]] 
    then 
        log "Adding the LDAP auth settings to guacamole.properties"
        (
            echo ""
            echo "# Properties used by the LDAP Authentication plugin"
            echo "ldap-hostname:           ${LDAP_HOSTNAME}"
            echo "ldap-port:               ${LDAP_PORT}"
            echo "ldap-user-base-dn:       ${LDAP_USER_BASE},${LDAP_DOMAIN_DN}"
            echo "ldap-username-attribute: ${LDAP_USER_ATTRIBUTE}"
            echo "ldap-config-base-dn:     ${LDAP_CONFIG_BASE},${LDAP_DOMAIN_DN}"
        ) >> /etc/guacamole/guacamole.properties
    elif [[ ${LDAP_PORT} -eq 636 ]] 
    then
        log "Adding the LDAPS auth settings to guacamole.properties"
        (
            echo ""
            echo "# Properties used by the LDAP Authentication plugin"
            echo "ldap-hostname:           ${LDAP_HOSTNAME}"
            echo "ldap-port:               ${LDAP_PORT}"
            echo "ldap-encryption-method:  ssl"
            echo "ldap-user-base-dn:       ${LDAP_USER_BASE},${LDAP_DOMAIN_DN}"
            echo "ldap-username-attribute: ${LDAP_USER_ATTRIBUTE}"
            echo "ldap-config-base-dn:     ${LDAP_CONFIG_BASE},${LDAP_DOMAIN_DN}"
        ) >> /etc/guacamole/guacamole.properties
        if [ -n "${LDAP_CERT}" ]
        then
            # Install LDAPS certificate not in public chain
            log "Downloading cert for LDAP Hostname not in public chain"
            retry 5 wget --timeout=10 \
            "${LDAP_CERT}" -O "${LDAP_HOSTNAME}.cer" || \
            die "Could not download ldap cert"
            log "Adding LDAP Cert to tomcat cacerts"
            #centos7 path to cacerts file, other OS may differ, may be able to remove if update-ca-trust works below
            keytool -import -trustcacerts -keystore /etc/pki/ca-trust/extracted/java/cacerts -storepass changeit -noprompt -alias "${LDAP_HOSTNAME}" -file "${LDAP_HOSTNAME}.cer"
            if [[ $? -ne 0 ]]
            then
                die "Failed to add cert to cacerts, check cert format"
            fi
            #add cert to local trust to prevent removale from jvm at update
            cp "${LDAP_HOSTNAME}.cer" /etc/pki/ca-trust/source/anchors/
            update-ca-trust enable; update-ca-trust extract
            if [[ $? -ne 0 ]]
            then
                die "Failed to update-ca-trust, check cert format"
            fi
        fi
    else
        log "Unknown LDAP port number"
        die "Unknown LDAP port number"
    fi

    # Enable LDAP group based authorization, configure location to find LDAP groups
    if [ -n "$LDAP_GROUP_BASE" ]
    then
        log "Adding the LDAP group base DN, RBAC is enabled."
        (
            echo "ldap-group-base-dn:      ${LDAP_GROUP_BASE},${LDAP_DOMAIN_DN}"
        ) >> /etc/guacamole/guacamole.properties
    fi
fi

if [ -n "${DUO_API_HOSTNAME}" ]
then
    # Install the Guacamole DUO auth extension
    log "Downloading Guacmole DUO extension"
    GUAC_DUO="guacamole-auth-duo-${GUAC_VERSION}"
    cd /root
    retry 5 wget --timeout=10 \
        "${GUAC_EXTENSIONS}/${GUAC_DUO}.tar.gz" -O "${GUAC_DUO}.tar.gz" || \
        die "Could not download duo extension"

    log "Extracting Guacamole duo extension"
    cd /root
    tar -xvf "${GUAC_DUO}.tar.gz" || \
        die "Could not extract Guacamole duo plugin"

    log "Installing Guacamole duo .jar file in the extensions directory"
    cp "${GUAC_DUO}/${GUAC_DUO}.jar" "/etc/guacamole/extensions"
    chmod 644 "/etc/guacamole/extensions/""${GUAC_DUO}.jar"
    log "Appending the DUO auth settings to guacamole.properties"
    (
        echo ""
        echo "# Properties used by the DUO Authentication plugin"
        echo "duo-api-hostname:        ${DUO_API_HOSTNAME}"
        echo "duo-integration-key:     ${DUO_INTKEY}"
        echo "duo-secret-key:          ${DUO_SECRET}"
        echo "duo-application-key:     ${DUO_APPKEY}"
    ) >> /etc/guacamole/guacamole.properties
fi

# Housekeeping
log "Creating shell-init profile files"
echo "export GUACAMOLE_HOME=/etc/guacamole" > /etc/profile.d/guacamole.sh
echo "setenv GUACAMOLE_HOME /etc/guacamole" > /etc/profile.d/guacamole.csh
chmod 744 /etc/profile.d/guacamole.sh
/etc/profile.d/guacamole.sh
log "Setting SEL contexts on shell-init files"
chcon system_u:object_r:bin_t:s0 /etc/profile.d/guacamole.*


log "Ensuring freerdp plugins are linked properly"
if [[ ! -d /usr/lib64/freerdp ]]
then
    mkdir /usr/lib64/freerdp
fi
cd /usr/lib64/freerdp
for FILE in /usr/local/lib/freerdp/*
do
    ln -sf ${FILE}
done
if [[ ! -d /usr/local/lib64/freerdp ]]
then
    mkdir /usr/local/lib64/freerdp
fi
cd /usr/local/lib64/freerdp
for FILE in /usr/local/lib/freerdp/*
do
    ln -sf ${FILE}
done


log "Creating directory for file transfers"
if [[ ! -d /var/tmp/guacamole ]]
then
    mkdir /var/tmp/guacamole
fi


#Add legal banner to Guacamole login page using Guac extensions.
one=1
if ( [[ "${BANNER}" == "${one}" ]] )
then
    write_manifest
    write_legal
else
    log "Banner parameter not set, not adding legal"
fi


sleep 2


#Add custom URLs to Guacamole login page using Guac extensions.
if ( [[ -n "${URL_1}" ]] || [[ -n "${URL_2}" ]] )
then
    write_manifest
    write_links
else
    log "URL parameters were blank, not adding links"
fi


#Add custom branding text to title page.
if [[ -n "${BRANDTEXT}" ]]
then
    write_manifest
    write_brand
else
   log "Branding text was blank, keeping default text"
fi


#Add custom logo to logon page.
if [[ -n "${LOGO_URL}" ]]
then
    write_manifest
    write_logo
else
   log "Logo URL parameter was blank, keeping default logo"
fi


# GUACAMOLE_HOME shell-init script environment variable not working (with selinux?), creating symlink and copying extensions to tomcat path
mkdir -p /usr/share/tomcat/.guacamole/{extensions,lib}
ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat/.guacamole/
ln -s /etc/guacamole/logback.xml /usr/share/tomcat/.guacamole/
cp /etc/guacamole/extensions/guacamole-auth-* /usr/share/tomcat/.guacamole/extensions/
log "If created earlier, copying custom.jar to guac home path"
if [[ -e /etc/guacamole/extensions/custom.jar ]] 
then
    cp /etc/guacamole/extensions/custom.jar /usr/share/tomcat/.guacamole/extensions/
fi

# Adjust firewalld
#firewall-offline-cmd --zone=public --permanent --add-service=https
firewall-offline-cmd --zone=public --add-service=https
service firewalld start
setenforce 0 && firewall-cmd --zone=public --permanent --add-service=https && setenforce 1
setenforce 0 && firewall-cmd --zone=public --add-service=https && setenforce 1
# Don't open 8080 when using apache httpd below
#firewall-cmd --zone=public --add-port=8080/tcp
#firewall-cmd --zone=public --permanent --add-port=8080/tcp


# Build self signed cert for use on apache httpd as proxy
log "Creating self-signed cert"
yum -y install mod_ssl openssl httpd
cd /root/
openssl req -nodes -sha256 -newkey rsa:2048 -keyout selfsigned.key -out selfsigned.csr -subj "/C=US/ST=ST/L=Loc/O=Org/OU=OU/CN=guac"
openssl x509 -req -sha256 -days 365 -in selfsigned.csr -signkey selfsigned.key -out selfsigned.crt
cp selfsigned.crt /etc/pki/tls/certs/
cp selfsigned.key /etc/pki/tls/private/
cp selfsigned.csr /etc/pki/tls/private/
# Configure Apache to use self signed cert
mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.bak
cd /etc/httpd/conf.d/
log "Writing new /etc/httpd/conf.d/ssl.conf"
(
    printf "LoadModule ssl_module modules/mod_ssl.so\n"
    printf "\n"
    printf "Listen 443\n"
    printf "\n"
    printf "SSLPassPhraseDialog  builtin\n"
    printf "\n"
    printf "SSLSessionCache         shmcb:/var/cache/mod_ssl/scache(512000)\n"
    printf "SSLSessionCacheTimeout  300\n"
    printf "\n"
    printf "SSLRandomSeed startup file:/dev/urandom  256\n"
    printf "SSLRandomSeed connect builtin\n"
    printf "SSLCryptoDevice builtin\n"
    printf "\n"
    printf "<VirtualHost _default_:443>\n"
    printf "ErrorLog logs/ssl_error_log\n"
    printf "TransferLog logs/ssl_access_log\n"
    printf "LogLevel warn\n"
    printf "SSLEngine On\n"
    printf "\n"
    printf "SSLCertificateFile /etc/pki/tls/certs/selfsigned.crt\n"
    printf "SSLCertificateKeyFile /etc/pki/tls/private/selfsigned.key\n"
    printf "\n"
    printf "BrowserMatch \".*MSIE.*\" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0\n"
    printf "\n"
    printf "ServerName guac\n"
    printf "ServerAlias guac\n"
    printf "\n"
    printf "ProxyRequests Off\n"
    printf "ProxyPreserveHost On\n"
    printf "ProxyPass / ws://localhost:8080/\n"
    printf "ProxyPassReverse / ws://localhost:8080/\n"
    printf "ProxyPass / http://localhost:8080/\n"
    printf "ProxyPassReverse / http://localhost:8080/\n"
    printf "\n"
    printf "</VirtualHost>\n"
    printf "\n"
    printf "SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH\n"
    printf "SSLProtocol -all -SSLv2 -SSLv3 +TLSv1.2\n"
    printf "SSLHonorCipherOrder On\n"
    printf "Header always set Strict-Transport-Security \"max-age=63072000; includeSubdomains; preload\"\n"
    printf "Header always set X-Frame-Options DENY\n"
    printf "Header always set X-Content-Type-Options nosniff\n"
    printf "SSLCompression off\n"
    printf "SSLUseStapling on\n"
    printf "SSLStaplingCache \"shmcb:logs/stapling-cache(150000)\"\n"
) > /etc/httpd/conf.d/ssl.conf
chmod 644 /etc/httpd/conf.d/ssl.conf


# Ensure varVol is large enough for Azure extensions
varsize=$(lvdisplay | awk '/varVol/{found=1}; /LV Size/ && found{print $3; exit}')
thisvarsize=${varsize%%.*}
if [ -n "${thisvarsize}" ]
then 
    if [ "${thisvarsize}" -ge 800 ]
    then 
        lvextend -L+2G /dev/VolGroup00/varVol
        resize2fs /dev/VolGroup00/varVol
    fi
fi

one=1
if ( [[ "${USE_MSI}" == "${one}" ]] )
then
    #get real certificate zip and configure httpd
    CERT_MSI_SCRIPT=https://raw.githubusercontent.com/ewierschke/ra/wip/scripts/msi-get-cert-and-password-for-httpd.sh
    retry 5 wget --timeout=10 \
    "${CERT_MSI_SCRIPT}" -O /usr/local/bin/msi-get-cert-and-password-for-httpd.sh || \
    die "Could not download msi script file" 
    chmod 755 /usr/local/bin/msi-get-cert-and-password-for-httpd.sh
    bash /usr/local/bin/msi-get-cert-and-password-for-httpd.sh -C ${CERTIFICATE_ZIP_URL} -S ${CERTIFICATE_KV_SECRET_URI} 
else
    log "USE_MSI parameter not set, not configuring real certificate"
fi


# Start services
log "Attempting to start services"
for SVC in rsyslog guacd tomcat httpd ntpd
do
    log "Stopping and starting ${SVC}"
    /sbin/service ${SVC} stop && /sbin/service ${SVC} start
    if [[ $? -ne 0 ]]
    then
      die "Failed to start ${SVC}."
    fi
done
log "Enabling services to start at next boot"
for SVC in tomcat guacd httpd ntpd
do
    chkconfig ${SVC} on
done


# Schedule yum update and reboot
(
    printf "yum -y update\n"
    printf "shutdown -r now\n"
) > /root/yumupdateandreboot.sh
chmod 755 /root/yumupdateandreboot.sh
yum -y install at
service atd start
chkconfig atd on
at now + 3 minutes -f /root/yumupdateandreboot.sh
