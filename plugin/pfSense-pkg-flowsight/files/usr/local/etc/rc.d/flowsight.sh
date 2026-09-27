#!/bin/sh
#
# FlowSight on pfSense. pfSense starts packages' /usr/local/etc/rc.d/*.sh
# scripts at boot with "start" and stops them with "stop"; there is no
# rc.conf switch, the package being installed is the switch. The daemon runs
# under daemon(8), which restarts it five seconds after it exits.

config=/usr/local/etc/flowsight/flowsight.json
pidfile=/var/run/flowsight/flowsightd.pid
supervisor_pidfile=/var/run/flowsight/daemon.pid
procname=/usr/local/sbin/flowsightd

# The pid of a live supervisor, if there is one.
supervisor()
{
    [ -f ${supervisor_pidfile} ] || return 1
    pid=$(cat ${supervisor_pidfile})
    [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null || return 1
    echo "${pid}"
}

# Every standard descriptor is redirected: the supervisor lives as long as
# the service, and whatever started it (the GUI, an SSH session) would
# otherwise wait on them forever.
start()
{
    if supervisor >/dev/null; then
        echo "flowsight is already running."
        return 0
    fi
    install -d -m 755 /var/run/flowsight /var/log/flowsight /var/db/flowsight /usr/local/etc/flowsight
    echo "Starting flowsight."
    /usr/sbin/daemon -f -S -T flowsightd -R 5 -P ${supervisor_pidfile} -p ${pidfile} \
        -o /var/log/flowsight/daemon.out ${procname} -config ${config} \
        </dev/null >/dev/null 2>&1
}

# Stop the supervisor, not the daemon: daemon(8) passes SIGTERM on and
# exits. Signalling only the daemon would have it started again.
stop()
{
    if ! pid=$(supervisor); then
        echo "flowsight is not running."
        return 0
    fi
    echo "Stopping flowsight."
    kill -TERM "${pid}"
    pwait -t 30 "${pid}" 2>/dev/null
    if kill -0 "${pid}" 2>/dev/null; then
        echo "flowsight did not stop within 30 seconds."
        return 1
    fi
}

status()
{
    if pid=$(supervisor); then
        echo "flowsight is running as pid $(cat ${pidfile} 2>/dev/null) (supervisor ${pid})."
    else
        echo "flowsight is not running."
        return 1
    fi
}

case "$1" in
start) start ;;
stop) stop ;;
restart) stop; start ;;
status) status ;;
*) echo "usage: $0 start|stop|restart|status"; exit 1 ;;
esac
