<?php

/*
 * FlowSight: OPNsense integration hooks.
 *
 * Registers the service so the GUI can start, stop and show it, and gives
 * the daemon two pf anchors it owns outright: "flowsight/*" as a filter
 * anchor at the head of the ruleset, so a policy block is seen before any
 * later pass rule, and the same anchor for rdr at the tail, so interception
 * only sees traffic no port forward already claimed (NAT reflection is an
 * rdr too, and must match first). Everything inside the anchors is loaded by
 * flowsightd with pfctl -a; nothing here writes rules itself.
 *
 * The filter anchor must never be registered quick. The block rules
 * flowsightd loads are quick themselves, and that is what makes a policy
 * block final. A quick anchor is something else: on OPNsense 26.7 (FreeBSD
 * 15.1), as soon as flowsightd had loaded anything into it (a sub-anchor
 * with no filter rules was enough), pf stopped evaluating every rule after
 * it for every packet, so the firewall's own ruleset, the default deny
 * included, was never reached.
 */

function flowsight_enabled()
{
    global $config;
    return isset($config['OPNsense']['flowsight']['general']['enabled']) &&
        $config['OPNsense']['flowsight']['general']['enabled'] == '1';
}

function flowsight_services()
{
    $services = [];
    if (flowsight_enabled()) {
        $services[] = [
            'description' => gettext('FlowSight'),
            'configd' => [
                'restart' => ['flowsight restart'],
                'start' => ['flowsight start'],
                'stop' => ['flowsight stop'],
            ],
            'name' => 'flowsight',
            'pidfile' => '/var/run/flowsight/flowsightd.pid',
        ];
    }
    return $services;
}

function flowsight_firewall(\OPNsense\Firewall\Plugin $fw)
{
    if (!flowsight_enabled()) {
        return;
    }
    $fw->registerAnchor('flowsight/*', 'rdr', 0, 'tail');
    $fw->registerAnchor('flowsight/*', 'nat', 0, 'tail');
    $fw->registerAnchor('flowsight/*', 'fw', 0, 'head', false);
}

function flowsight_syslog()
{
    $logfacilities = [];
    $logfacilities['flowsight'] = ['facility' => ['flowsightd']];
    return $logfacilities;
}
