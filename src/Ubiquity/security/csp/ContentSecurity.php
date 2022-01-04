<?php
namespace Ubiquity\security\csp;

use Ubiquity\controllers\Startup;
use Ubiquity\utils\http\UResponse;

/**
 * Creates a Content Security Policy object.
 * Ubiquity\security\csp$ContentSecurity
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class ContentSecurity {

	const HEADER = 'Content-Security-Policy';

	const DEBUG_HEADER = 'Content-Security-Policy-Report-Only';

	private array $policies = [];

	private $header = self::HEADER;

	/**
	 * ContentSecurity constructor.
	 *
	 * @param bool|null $reportOnly
	 */
	public function __construct(?bool $reportOnly = null) {
		if (isset($reportOnly)) {
			$this->reportOnly($reportOnly);
		}
	}

	/**
	 * Adds new values to a directive.
	 *
	 * @param string $directive
	 * @param string ...$values
	 * @return $this
	 */
	public function addPolicy(string $directive, string ...$values): self {
		$policies = $this->policies[$directive] ?? [];
		foreach ($values as $v) {
			if (\in_array($v, CspValues::QUOTED)) {
				$v = "'$v'";
			}
			$policies[$v] = true;
		}
		$this->policies[$directive] = $policies;
		return $this;
	}

	public function removePolicy(string $directive, string ...$values): self {
		$policies = $this->policies[$directive] ?? [];
		foreach ($values as $v) {
			if (\in_array($v, CspValues::QUOTED)) {
				$v = "'$v'";
			}
			if (isset($this->policies[$directive][$v])) {
				unset($this->policies[$directive][$v]);
			}
		}
		return $this;
	}

	/**
	 * Adds new values to a directive, re-using default-src actual values.
	 *
	 * @param string $directive
	 * @param string ...$values
	 * @return $this
	 */
	public function addPolicyDefault(string $directive, string ...$values): self {
		$default = \array_keys($this->policies[CspDirectives::DEFAULT_SRC] ?? []);
		$values = \array_merge($default, $values);
		$this->addPolicy($directive, ...$values);
		return $this;
	}

	/**
	 * Adds a nonce to the directives.
	 *
	 * @param string $nonce
	 * @param string ...$directives
	 * @return $this
	 */
	public function addNonce(string $nonce, string ...$directives): self {
		foreach ($directives as $directive) {
			$this->addPolicy($directive, "'nonce-$nonce'", CspValues::STRICT_DYNAMIC);
		}
		return $this;
	}

	/**
	 * Adds a hash to the directives.
	 *
	 * @param string $hash
	 * @param string ...$directives
	 * @return $this
	 */
	public function addHash(string $hash, string ...$directives): self {
		foreach ($directives as $directive) {
			$this->addPolicy($directive, "'$hash'");
		}
		return $this;
	}

	/**
	 * Adds a nonce to a directive, re-using default-src actual values.
	 *
	 * @param string $nonce
	 * @param string ...$directives
	 * @return $this
	 */
	public function addNonceDefault(string $nonce, string ...$directives): self {
		foreach ($directives as $directive) {
			$this->addPolicyDefault($directive, "'nonce-$nonce'", CspValues::STRICT_DYNAMIC);
		}
		return $this;
	}

	/**
	 * Adds a hash to a directive, re-using default-src actual values.
	 *
	 * @param string $hash
	 * @param string ...$directives
	 * @return $this
	 */
	public function addHashDefault(string $hash, string ...$directives): self {
		foreach ($directives as $directive) {
			$this->addPolicyDefault($directive, "'$hash'");
		}
		return $this;
	}

	/**
	 * Defines the policies for default-src directive.
	 *
	 * @param string ...$policies
	 * @return $this
	 */
	public function setDefaultSrc(string ...$policies): self {
		return $this->addPolicy(CspDirectives::DEFAULT_SRC, ...$policies);
	}

	/**
	 * Generates the header string.
	 *
	 * @return string
	 */
	public function generate(): string {
		$strs = '';
		foreach ($this->policies as $directive => $policy) {
			$policies = \array_keys($policy);
			$strs .= $directive . ' ' . \implode(' ', $policies) . ';';
		}
		return $strs;
	}

	/**
	 * Display a ContentSecurity object.
	 *
	 * @param callable $directiveCall
	 * @param callable $policyCall
	 * @return string
	 */
	public function display(callable $directiveCall, callable $policyCall): string {
		$strs = '';
		foreach ($this->policies as $directive => $policy) {
			$policies = \array_keys($policy);
			$strs .= $directiveCall($directive) . $policyCall(\implode(' ', $policies));
		}
		return $strs;
	}

	/**
	 * Sets reportOnly.
	 *
	 * @param bool|null $reportOnly
	 * @return $this
	 */
	public function reportOnly(?bool $reportOnly = true): self {
		if (isset($reportOnly)) {
			$this->header = $reportOnly ? self::DEBUG_HEADER : self::HEADER;
		}
		return $this;
	}

	/**
	 * Adds headers to the response.
	 *
	 * @param bool|null $reportOnly
	 */
	public function addHeaderToResponse(?bool $reportOnly = null): void {
		if (isset($reportOnly)) {
			$this->reportOnly($reportOnly);
		}
		UResponse::header($this->header, $this->generate(), false);
	}

	/**
	 * Creates a nonce and add it to some directives.
	 *
	 * @param
	 *        	$nonce
	 * @param string ...$directives
	 * @return ContentSecurity
	 */
	public static function nonce($nonce, string ...$directives): ContentSecurity {
		$csp = new self();
		return $csp->addNonce($nonce, ...$directives);
	}

	/**
	 * Creates a new ContentSecurity object, with self in default-src.
	 *
	 * @return ContentSecurity
	 */
	public static function all(): ContentSecurity {
		$csp = new self();
		return $csp->addPolicy(CspDirectives::DEFAULT_SRC, CspValues::SELF);
	}

	/**
	 * Returns the actual policies.
	 *
	 * @return array
	 */
	public function getPolicies(): array {
		return $this->policies;
	}

	/**
	 * Creates a new ContentSecurity object for Ubiquity Webtools.
	 *
	 * @return ContentSecurity
	 */
	public static function defaultUbiquity(): ContentSecurity {
		$csp = new self();
		$csp->addPolicyDefault(CspDirectives::CONNECT_SRC, CspValues::SELF);
		$csp->addPolicy(CspDirectives::IMG_SRC, 'data:');
		return $csp;
	}

	/**
	 * Creates a new ContentSecurity object for Ubiquity Webtools in debug mode.
	 *
	 * @param string $livereloadServer
	 * @return ContentSecurity
	 */
	public static function defaultUbiquityDebug(string $livereloadServer = '127.0.0.1:35729'): ContentSecurity {
		$csp = self::defaultUbiquity();
		$config = Startup::$config;
		if ($config['debug'] && \Ubiquity\debug\LiveReload::hasLiveReload()) {
			$csp->addPolicyDefault(CspDirectives::CONNECT_SRC, "ws://$livereloadServer");
		}
		return $csp;
	}
}
