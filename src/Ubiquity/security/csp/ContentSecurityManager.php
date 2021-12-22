<?php
namespace Ubiquity\security\csp;

class ContentSecurityManager {

	private static NonceGenerator $nonceGenerator;

	public static function start(string $nonceGeneratorClass = null) {
		$nonceGeneratorClass ??= NonceGenerator::class;
		self::$nonceGenerator = new $nonceGeneratorClass();
	}

	public static function getNonce(string $name) {
		return self::$nonceGenerator->getNonce($name);
	}

	public static function isStarted(): bool {
		return isset(self::$nonceGenerator);
	}
}

