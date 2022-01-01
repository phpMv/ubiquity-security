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

	/**
	 * Starts the Content Security Policies manager.
	 *
	 * @param string|null $nonceGeneratorClass
	 *        	The class used for generating nonces.
	 * @param bool $reportOnly
	 * @param callable|null $onNonce
	 */
	public static function start(string $nonceGeneratorClass = null, bool $reportOnly = false, ?callable $onNonce = null): void {
		$nonceGeneratorClass ??= NonceGenerator::class;
		self::$nonceGenerator = new $nonceGeneratorClass($onNonce);
		self::$reportOnly = $reportOnly;
	}

	/**
	 * Returns a new or an existing nonce.
	 *
	 * @param string $name
	 *        	The nonce to create
	 * @return string
	 */
	public static function getNonce(string $name): string {
		return self::$nonceGenerator->getNonce($name);
	}

	/**
	 *
	 * @param string $name
	 * @return bool
	 */
	public static function hasNonce(string $name): bool {
		if (isset(self::$nonceGenerator)) {
			return self::$nonceGenerator->hasNonce($name);
		}
		return false;
	}

	/**
	 * Checks if the manager is started.
	 *
	 * @return bool
	 */
	public static function isStarted(): bool {
		return isset(self::$nonceGenerator);
	}

	/**
	 * Creates and returns a new ContentSecurity object.
	 *
	 * @param bool|null $reportOnly
	 * @return ContentSecurity
	 */
	public static function addCsp(?bool $reportOnly = null): ContentSecurity {
		return self::$csp[] = new ContentSecurity($reportOnly ?? self::$reportOnly);
	}

	/**
	 * Removes all CSP objects.
	 */
	public static function clearCsp(): void {
		self::$csp = [];
	}

	/**
	 * Creates a new ContentSecurity object for Ubiquity Webtools.
	 *
	 * @param bool|null $reportOnly
	 * @return ContentSecurity
	 */
	public static function defaultUbiquity(?bool $reportOnly = null): ContentSecurity {
		return self::$csp[] = ContentSecurity::defaultUbiquity()->reportOnly($reportOnly);
	}

	/**
	 * Creates a new ContentSecurity object for Ubiquity Webtools in debug mode.
	 *
	 * @param bool|null $reportOnly
	 * @param string $livereloadServer
	 * @return ContentSecurity
	 */
	public static function defaultUbiquityDebug(?bool $reportOnly = null, string $livereloadServer = '127.0.0.1:35729'): ContentSecurity {
		return self::$csp[] = ContentSecurity::defaultUbiquityDebug($livereloadServer)->reportOnly($reportOnly);
	}

	/**
	 * Adds all Content security policies to headers.
	 *
	 * @param bool|null $reportOnly
	 */
	public static function addHeadersToResponse(?bool $reportOnly = null): void {
		$reportOnly ??= self::$reportOnly;
		foreach (self::$csp as $csp) {
			$csp->addHeaderToResponse($reportOnly);
		}
	}

	/**
	 * Returns the NonceGenerator instance.
	 *
	 * @return NonceGenerator
	 */
	public static function getNonceGenerator(): NonceGenerator {
		return self::$nonceGenerator;
	}

	/**
	 *
	 * @return array
	 */
	public static function getCsp(): array {
		return self::$csp;
	}

	/**
	 * Returns true if reportOnly header is activated.
	 *
	 * @return bool
	 */
	public static function isReportOnly(): bool {
		return self::$reportOnly;
	}
}
