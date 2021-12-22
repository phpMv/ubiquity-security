<?php
namespace Ubiquity\security\csp;

use Ubiquity\utils\http\URequest;

class NonceGenerator {

	private array $nonces = [];

	protected function _generateNonce(string $name, ?int $value = null): string {
		$bytes = \random_bytes((int) ($value ?? 32));
		$nonce = \base64_encode($bytes);
		if (! URequest::isAjax()) {
			$this->onNonce($name, $nonce);
		}
		return $nonce;
	}

	public function getNonce(string $name) {
		return $this->nonces[$name] ??= self::_generateNonce($name, $value);
	}

	function onNonce(string $name, string $value) {}
}

