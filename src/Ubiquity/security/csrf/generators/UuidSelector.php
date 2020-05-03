<?php
namespace Ubiquity\security\csrf\generators;

class UuidSelector implements GeneratorInterface {

	public function generate(?string $value = null): string {
		return uniqid($value ?? '', true);
	}
}

