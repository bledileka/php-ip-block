<?php
/*
 * Block ip/range from accessing a web page.
 */

namespace Bledileka\Ipblocker;

class Verifyip
{
	public function __construct($configs)
	{

		if (isset($configs["ip_address"]) && $configs["ip_address"] != "") {
			//use the provided ip address
			$this->ip = trim($configs["ip_address"]);
		} else {
			$this->ip = $this->detectIP();
		}
		if (isset($configs["whitelist"])) {
			$this->whitelist = $configs["whitelist"];
		}
		if (isset($configs["lists"])) {
			$this->lists = $configs["lists"];
		}
		if (isset($configs["custom"])) {
			$this->custom = $configs["custom"];
		}
		if (isset($configs["blocked_redirect_to_url"])) {
			$this->redir_url = $configs["blocked_redirect_to_url"];
		}
		$stop = 0;

		if ($this->ip != "") {

			$whitelisted = $this->isWhitelisted();

			if ($whitelisted != 1) {
				// current ip is not whitelisted, proceed to other checks
				$CustomBlacklisted = $this->isBlacklistedCustom();
				if ($CustomBlacklisted == 1) {
					// we have a custom blacklisting rule!
					$stop = 1;
				} else {
					// last option go throught the rest of the lists
					$islisted = $this->isBlaclistedLists();
					if ($islisted == 1) {
						$stop = 1;
					}
				}
			}

		}
		// if no ip do nothing

		if ($stop == 1) {
			if (isset($this->redir_url) && $this->redir_url != "") {
				header("Location: " . $this->redir_url);
			}
			die("Sorry, your IP address (" . $this->ip . ") is not allowed to access this page!");
		}


	}

	function isBlaclistedLists()
	{

		if (isset($this->lists) && is_array($this->lists) && count($this->lists) > 0) {
			$found = 0;
			foreach ($this->lists as $list) {
				$file = __DIR__ . "/ip_ranges/" . $list;
				if (file_exists($file)) {
					$file = fopen($file, "r");
					while (!feof($file)) {
						$rangeip = trim(fgets($file));
						$exists = $this->isInrange($this->ip, $rangeip);
						if (isset($exists) && $exists == 1) {
							$found = 1;
							break;
						}
					}
					fclose($file);
				}
			}

			return $found;
		}
	}

	function isBlacklistedCustom()
	{
		$found = 0;
		if (isset($this->custom)) {
			foreach ($this->custom as $rangeip) {
				$exists = $this->isInrange($this->ip, $rangeip);
				if (isset($exists) && $exists == 1) {
					$found = 1;
					break;
				}
			}
		}

		return $found;
	}

	function isWhitelisted()
	{
		$found = 0;
		if (isset($this->whitelist)) {
			foreach ($this->whitelist as $rangeip) {
				$exists = $this->isInrange($this->ip, $rangeip);
				if (isset($exists) && $exists == 1) {
					$found = 1;
					break;
				}
			}
		}
		return $found;
	}


	public function isInrange($ip, $range)
	{
		if (strpos($range, '/') === false) {
			$range .= '/32';
		}
		list($range, $netmask) = explode('/', $range, 2);
		$range_decimal = ip2long($range);
		$ip_decimal = ip2long($ip);
		$wildcard_decimal = pow(2, (32 - $netmask)) - 1;
		$netmask_decimal = ~$wildcard_decimal;
		return (($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal));
	}

	function detectIP()
	{
		$ipaddress = '';
		if (getenv('HTTP_CLIENT_IP'))
			$ipaddress = getenv('HTTP_CLIENT_IP');
		else if (getenv('HTTP_X_FORWARDED_FOR'))
			$ipaddress = getenv('HTTP_X_FORWARDED_FOR');
		else if (getenv('HTTP_X_FORWARDED'))
			$ipaddress = getenv('HTTP_X_FORWARDED');
		else if (getenv('HTTP_FORWARDED_FOR'))
			$ipaddress = getenv('HTTP_FORWARDED_FOR');
		else if (getenv('HTTP_FORWARDED'))
			$ipaddress = getenv('HTTP_FORWARDED');
		else if (getenv('REMOTE_ADDR'))
			$ipaddress = getenv('REMOTE_ADDR');
		return $ipaddress;
	}

}