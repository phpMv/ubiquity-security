<?php
namespace Ubiquity\security\csp;

use Ubiquity\utils\http\URequest;

class NonceGenerator {

	private array $nonces = [];

	private $onNonce;

	public function __construct(?callable $onNonce) {
		$this->onNonce = $onNonce;
	}

	protected function _generateNonce(string $name, ?int $value = null): string {
		$bytes = \random_bytes((int) ($value ?? 32));
		$nonce = \base64_encode($bytes);
		if (isset($this->onNonce) && ! URequest::isAjax()) {
			$onNonce=$this->onNonce;
			$onNonce($name, $nonce);
		}
		return $nonce;
	}

	public function getNonce(string $name,int $size=32) {
		return $this->nonces[$name] ??= self::_generateNonce($name, $size);
	}
}

