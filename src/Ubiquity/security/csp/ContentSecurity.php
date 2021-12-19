<?php
namespace src\Ubiquity\security\csp;

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

	public function addPolicy(string $directive, array ...$values): self {
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

	public function setDefaultSrc(array ...$policies) {
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

	public function addHeaderToResponse(): void {
		UResponse::header(self::HEADER, $this->generate());
	}
}

