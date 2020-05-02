<?php
namespace Ubiquity\security\csrf\generators;

use Ubiquity\security\csrf\genetators\GeneratorInterface;

class Md5Selector implements GeneratorInterface {

	public function generate($value = null) {
		return md5($value ?? '');
	}
}

