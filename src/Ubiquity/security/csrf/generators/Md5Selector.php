<?php
namespace Ubiquity\security\csrf\generators;

class Md5Selector implements GeneratorInterface {

	public function generate(?string $value = null): string {
		return md5($value ?? '');
	}
}

