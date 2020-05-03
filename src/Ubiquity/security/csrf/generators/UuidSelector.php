<?php
namespace Ubiquity\security\csrf\generators;

class UuidSelector implements GeneratorInterface {

	public function generate($value = null) {
		return uniqid($value ?? '', true);
	}
}

