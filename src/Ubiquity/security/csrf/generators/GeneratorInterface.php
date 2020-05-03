<?php
namespace Ubiquity\security\csrf\generators;

interface GeneratorInterface {

	public function generate(?string $value = null): string;
}

