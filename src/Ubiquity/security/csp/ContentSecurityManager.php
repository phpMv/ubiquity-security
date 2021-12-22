<?php
namespace Ubiquity\security\csp;

/**
 * Manage Content Security Policies.
 * Ubiquity\security\csp$ContentSecurityManager
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class ContentSecurityManager {

	private static NonceGenerator $nonceGenerator;

	private static array $csp = [];

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

	public static function addCsp(?bool $reportOnly = null): ContentSecurity {
		return self::$csp[] = new ContentSecurity($reportOnly);
	}

	public static function clearCsp() {
		self::$csp = [];
	}

	public static function addHeadersToResponse(?bool $reportOnly = null): void {
		foreach (self::$csp as $csp) {
			$csp->addHeaderToResponse($reportOnly);
		}
	}
}

