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

	public function addNonce(string $nonce, string ...$directives): self {
		$directives ??= [
			CspDirectives::DEFAULT_SRC
		];
		foreach ($directives as $directive) {
			$this->policies[$directive]["'nonce-$nonce'"] = true;
			$this->policies[$directive][CspValues::STRICT_DYNAMIC] = true;
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

	public function reportOnly(bool $reportOnly = true): self {
		$this->header = $reportOnly ? self::DEBUG_HEADER : self::HEADER;
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

	public static function defaultUbiquity(): ContentSecurity {
		$csp = new self();
		$csp->addPolicy(CspDirectives::DEFAULT_SRC, 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com');
		$csp->addPolicy(CspDirectives::FONT_SRC, 'fonts.googleapis.com', 'fonts.gstatic.com', 'data:');
		$csp->addPolicy(CspDirectives::STYLE_SRC_ELM, CspValues::UNSAFE_INLINE);
		return $csp;
	}
}

