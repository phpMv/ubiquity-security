<?php
namespace Ubiquity\security\csrf\generators;

class RandomValidator implements GeneratorInterface {

	public function generate($value = null) {
		$bytes = random_bytes($value ?? 32);
		return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
	}
}

