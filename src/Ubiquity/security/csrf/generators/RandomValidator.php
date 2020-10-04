<?php
namespace Ubiquity\security\csrf\generators;

class RandomValidator implements GeneratorInterface {

	public function generate(?string $value = null): string {
		$bytes = random_bytes((int) ($value ?? 32));
		return \rtrim(\strtr(\base64_encode($bytes), '+/', '-_'), '=');
	}
}

