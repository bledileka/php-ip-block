<?php
require_once __DIR__ . '/vendor/autoload.php';

//leave the following array empty if you need to block single ips (faster)
$blockRanges = [
	"digitalocean.txt",
	"vultr.txt",
	"azure.txt",
	"aws.txt",
	"alicloud.txt"
];

$custom = [
	"127.0.0.2"
];

$whitelist = [
	"127.0.0.3",
	"::1",
];

$block = new Bledileka\Ipblocker\Verifyip (
	[
		"ip_address" => "67.207.68.6", //pass the users ip address or leave it empty for autodetection - works only for http requests
		"blocked_redirect_to_url" => "", //if user is coming from one of the blocked ranges then redir
		"lists" => [],
		"custom" => [],
		"whitelist" => []
	]
);



?>