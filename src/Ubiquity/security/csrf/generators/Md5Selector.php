<?php
namespace Ubiquity\security\csrf\generators;

class Md5Selector implements GeneratorInterface {

	public function generate($value = null) {
		return md5($value ?? '');
	}
}

