<?php
namespace Ubiquity\security\csp;

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

	public function __construct(?bool $reportOnly = null) {
		if (isset($reportOnly)) {
			$this->reportOnly($reportOnly);
		}
	}

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

	public function addPolicyDefault(string $directive, string ...$values): self {
		$default = \array_keys($this->policies[CspDirectives::DEFAULT_SRC] ?? []);
		$values = \array_merge($default, $values);
		$this->addPolicy($directive, ...$values);
		return $this;
	}

	public function addNonce(string $nonce, string ...$directives): self {
		foreach ($directives as $directive) {
			$this->addPolicy($directive, "'nonce-$nonce'", CspValues::STRICT_DYNAMIC);
		}
		return $this;
	}

	public function addNonceDefault(string $nonce, string ...$directives): self {
		foreach ($directives as $directive) {
			$this->addPolicyDefault($directive, "'nonce-$nonce'", CspValues::STRICT_DYNAMIC);
		}
		return $this;
	}

	public function setDefaultSrc(string ...$policies) {
		return $this->addPolicy(CspDirectives::DEFAULT_SRC, ...$policies);
	}

	public function generate(): string {
		$strs = '';
		foreach ($this->policies as $directive => $policy) {
			$policies = \array_keys($policy);
			$strs .= $directive . ' ' . \implode(' ', $policies) . ';';
		}
		return $strs;
	}

	public function reportOnly(?bool $reportOnly = true): self {
		if (isset($reportOnly)) {
			$this->header = $reportOnly ? self::DEBUG_HEADER : self::HEADER;
		}
		return $this;
	}

	public function addHeaderToResponse(?bool $reportOnly = null): void {
		if (isset($reportOnly)) {
			$this->reportOnly($reportOnly);
		}
		UResponse::header($this->header, $this->generate(), false);
	}

	public static function nonce($nonce, string ...$directives): ContentSecurity {
		$csp = new self();
		return $csp->addNonce($nonce, ...$directives);
	}

	public static function all(): ContentSecurity {
		$csp = new self();
		return $csp->addPolicy(CspDirectives::DEFAULT_SRC, CspValues::SELF);
	}

	public static function defaultUbiquity(): ContentSecurity {
		$csp = new self();
		$csp->addPolicy(CspDirectives::DEFAULT_SRC, 'self', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com');
		$csp->addPolicyDefault(CspDirectives::FONT_SRC, 'fonts.googleapis.com', 'fonts.gstatic.com', 'data:');
		$csp->addPolicyDefault(CspDirectives::STYLE_SRC, CspValues::UNSAFE_INLINE, 'fonts.googleapis.com');
		$csp->addPolicyDefault(CspDirectives::SCRIPT_SRC_ELM, CspValues::UNSAFE_INLINE);
		$csp->addPolicy(CspDirectives::IMG_SRC, 'data:');
		return $csp;
	}
}
