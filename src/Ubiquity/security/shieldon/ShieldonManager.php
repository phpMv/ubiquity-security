<?php
namespace Ubiquity\security\shieldon;

use Psr\Http\Message\ResponseInterface;
use Shieldon\Firewall\Firewall;
use Shieldon\Firewall\HttpResolver;
use Shieldon\Firewall\Panel;

/**
 * Ubiquity\security\shieldon$ShieldonManager
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class ShieldonManager {

	private static Firewall $firewall;

	public static function getFirewall(): Firewall {
		return self::$firewall;
	}

	/**
	 * Starts th Shieldon service.
	 *
	 * @param string $writable
	 */
	public static function start(string $writable = null): void {
		$writable ??= \ROOT . \DS . 'cache' . \DS . 'shieldon';
		self::$firewall = new Firewall();
		self::$firewall->configure($writable);
		$response = self::$firewall->run();
		if ($response->getStatusCode() !== 200) {
			$httpResolver = new HttpResolver();
			$httpResolver($response);
		}
	}

	/**
	 * Creates the admin panel.
	 */
	public static function createPanel(string $uri): Panel {
		$panel = new Panel();
		self::$firewall->controlPanel($uri);
		return $panel;
	}

	/**
	 *
	 * @return ResponseInterface
	 */
	public static function run(): ResponseInterface {
		return self::$firewall->run();
	}
}
