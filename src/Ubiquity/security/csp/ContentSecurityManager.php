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

	private static bool $reportOnly;

	public static function start(string $nonceGeneratorClass = null, bool $reportOnly = false, ?callable $onNonce = null) {
		$nonceGeneratorClass ??= NonceGenerator::class;
		self::$nonceGenerator = new $nonceGeneratorClass($onNonce);
		self::$reportOnly = $reportOnly;
	}

	public static function getNonce(string $name) {
		return self::$nonceGenerator->getNonce($name);
	}

	public static function isStarted(): bool {
		return isset(self::$nonceGenerator);
	}

	public static function addCsp(?bool $reportOnly = null): ContentSecurity {
		return self::$csp[] = new ContentSecurity($reportOnly ?? self::$reportOnly);
	}

	public static function clearCsp() {
		self::$csp = [];
	}

	public static function defaultUbiquity(?bool $reportOnly = null): ContentSecurity {
		return self::$csp[] = ContentSecurity::defaultUbiquity()->reportOnly($reportOnly);
	}

	public static function addHeadersToResponse(?bool $reportOnly = null): void {
		$reportOnly ??= self::$reportOnly;
		foreach (self::$csp as $csp) {
			$csp->addHeaderToResponse($reportOnly);
		}
	}
}

