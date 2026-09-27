<?php
/* The GUI privilege for FlowSight's page: its app, assets and API are all
 * served through flowsight.php, so this one privilege covers FlowSight. */
global $priv_list;

$priv_list['page-services-flowsight'] = array();
$priv_list['page-services-flowsight']['name'] = "WebCfg - Services: FlowSight";
$priv_list['page-services-flowsight']['descr'] = "Allow access to FlowSight (Services > FlowSight), including changing its policy.";
$priv_list['page-services-flowsight']['match'] = array();
$priv_list['page-services-flowsight']['match'][] = "flowsight.php*";
