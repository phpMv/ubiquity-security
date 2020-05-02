<?php
namespace Ubiquity\security\csrf\generators;

use Ubiquity\security\csrf\genetators\GeneratorInterface;

class UuidSelector implements GeneratorInterface {

	public function generate($value = null) {
		return uniqid($value ?? '', true);
	}
}

