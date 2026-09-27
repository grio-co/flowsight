<?php
/*
 * FlowSight: pfSense integration hooks.
 *
 * pfSense regenerates its ruleset and its resolver configuration from
 * config.xml on every change, so FlowSight hooks into both generators rather
 * than editing their output:
 *
 *   - the package filter hook (filter_rule_function in info.xml) gives
 *     flowsightd three pf anchors it owns outright: "flowsight/*" as a quick
 *     filter anchor, first of all filter rules (pfearly), so a policy block
 *     wins over any later pass rule; and nat-anchor and rdr-anchor
 *     "flowsight/*" after pfSense's own translation (nat), so interception
 *     only sees traffic no port forward or reflection already claimed;
 *   - three lines in the resolver's custom options include
 *     /var/unbound/flowsight/*.conf, the one directory flowsightd writes;
 *   - the alias flowsight_local, the root table FlowSight's rules use for
 *     "not local", which pfSense would otherwise delete on every reload.
 *
 * Everything inside the anchors and that directory is written by flowsightd;
 * nothing here writes a rule. Removing the package takes out exactly what
 * this file added.
 */

require_once("config.inc");
require_once("util.inc");
require_once("service-utils.inc");

define('FLOWSIGHT_UNBOUND_DIR', '/var/unbound/flowsight');
define('FLOWSIGHT_UNBOUND_MARK', '# FlowSight: added by pfSense-pkg-flowsight, removed with it');
define('FLOWSIGHT_RC', '/usr/local/etc/rc.d/flowsight.sh');

function flowsight_generate_rules($type)
{
	switch ($type) {
	case 'pfearly':
		return "anchor \"flowsight/*\" quick\n";
	case 'nat':
		return "nat-anchor \"flowsight/*\"\nrdr-anchor \"flowsight/*\"\n";
	}
	return "";
}

/* The lines FlowSight adds to the resolver's custom options. They follow
 * the forward zones, so the server clause is opened again first. */
function flowsight_unbound_lines()
{
	return array(FLOWSIGHT_UNBOUND_MARK, "server:", "include: " . FLOWSIGHT_UNBOUND_DIR . "/*.conf");
}

/* The custom options without FlowSight's lines, as an array of lines. */
function flowsight_unbound_without($lines)
{
	$ours = flowsight_unbound_lines();
	$out = array();
	for ($i = 0; $i < count($lines); $i++) {
		if (rtrim($lines[$i]) === $ours[0] &&
		    rtrim($lines[$i + 1] ?? '') === $ours[1] &&
		    rtrim($lines[$i + 2] ?? '') === $ours[2]) {
			$i += 2;
			continue;
		}
		$out[] = $lines[$i];
	}
	while (count($out) > 0 && trim(end($out)) === '') {
		array_pop($out);
	}
	return $out;
}

function flowsight_unbound_include($add)
{
	$cur = base64_decode(config_get_path('unbound/custom_options', ''));
	$lines = ($cur === '' || $cur === false) ? array() : explode("\n", str_replace("\r", "", $cur));
	$lines = flowsight_unbound_without($lines);
	if ($add) {
		$lines = array_merge($lines, flowsight_unbound_lines());
	}
	$new = implode("\n", $lines);
	if ($new === (string)$cur) {
		return false;
	}
	config_set_path('unbound/custom_options', base64_encode($new));
	return true;
}

/*
 * FlowSight's rules say "to anything not local" with the root table
 * <flowsight_local>. After every filter reload pfSense deletes each root
 * table that is not an alias, so the table is an alias: pfSense then
 * declares it, with the ranges below, on every reload, and keeps it.
 * flowsightd adds this network's own local networks within seconds.
 */
define('FLOWSIGHT_ALIAS', 'flowsight_local');

function flowsight_alias_ranges()
{
	return array("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
	    "224.0.0.0/4", "fc00::/7", "fe80::/10", "::1/128", "ff00::/8");
}

/* The index of the alias in config.xml, or -1. */
function flowsight_alias_index()
{
	foreach (config_get_path('aliases/alias', []) as $i => $a) {
		if (($a['name'] ?? '') === FLOWSIGHT_ALIAS) {
			return $i;
		}
	}
	return -1;
}

function flowsight_alias_add()
{
	$ranges = flowsight_alias_ranges();
	$alias = array(
		'name' => FLOWSIGHT_ALIAS,
		'type' => 'network',
		'address' => implode(' ', $ranges),
		'descr' => 'FlowSight: local networks (FlowSight keeps this current; removed with the package)',
		'detail' => implode('||', array_fill(0, count($ranges), 'FlowSight')),
	);
	$aliases = config_get_path('aliases/alias', []);
	$i = flowsight_alias_index();
	if ($i >= 0) {
		if ($aliases[$i] == $alias) {
			return false;
		}
		$aliases[$i] = $alias;
	} else {
		$aliases[] = $alias;
	}
	config_set_path('aliases/alias', $aliases);
	return true;
}

/* Remove the alias unless one of the operator's own rules uses it. */
function flowsight_alias_remove()
{
	$i = flowsight_alias_index();
	if ($i < 0) {
		return false;
	}
	foreach (array('filter/rule', 'nat/rule', 'nat/outbound/rule') as $path) {
		foreach (config_get_path($path, []) as $r) {
			if (strpos(serialize($r), FLOWSIGHT_ALIAS) !== false) {
				log_error("FlowSight: alias " . FLOWSIGHT_ALIAS . " left in place, a rule uses it");
				return false;
			}
		}
	}
	$aliases = config_get_path('aliases/alias', []);
	unset($aliases[$i]);
	config_set_path('aliases/alias', array_values($aliases));
	return true;
}

function flowsight_install()
{
	safe_mkdir(FLOWSIGHT_UNBOUND_DIR, 0755);
	@chown(FLOWSIGHT_UNBOUND_DIR, 'unbound');
	/* The include is a pattern; a file always matches it. */
	$placeholder = FLOWSIGHT_UNBOUND_DIR . '/00-flowsight.conf';
	if (!file_exists($placeholder)) {
		file_put_contents($placeholder, "# FlowSight writes its resolver includes in this directory.\n");
	}
	$changed = flowsight_unbound_include(true);
	$changed = flowsight_alias_add() || $changed;
	if ($changed) {
		write_config("FlowSight: resolver include and local-networks alias");
	}
	if (config_path_enabled('unbound')) {
		require_once("unbound.inc");
		services_unbound_configure();
	}
	filter_configure();
}

function flowsight_deinstall()
{
	if (file_exists(FLOWSIGHT_RC)) {
		mwexec(FLOWSIGHT_RC . " stop");
	}
	/* Withdraw everything FlowSight put in front of traffic first; policy
	 * and data stay in /usr/local/etc/flowsight and /var/db/flowsight. */
	foreach (array('web', 'enroll') as $a) {
		mwexec("/sbin/pfctl -a flowsight/{$a} -F nat");
	}
	foreach (array('policy', 'enroll', 'qos') as $a) {
		mwexec("/sbin/pfctl -a flowsight/{$a} -F rules");
		mwexec("/sbin/pfctl -a flowsight/{$a} -F Tables");
	}
	$changed = flowsight_unbound_include(false);
	$changed = flowsight_alias_remove() || $changed;
	if ($changed) {
		write_config("FlowSight: removed its resolver include and local-networks alias");
	}
	rmdir_recursive(FLOWSIGHT_UNBOUND_DIR);
	if (config_path_enabled('unbound')) {
		require_once("unbound.inc");
		services_unbound_configure();
	}
}
