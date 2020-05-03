<?php
namespace Ubiquity\security\csrf\generators;

interface GeneratorInterface {

	public function generate($value = null): string;
}

