<?php
namespace Ubiquity\security\csrf\genetators;

interface GeneratorInterface {

	public function generate($value = null): string;
}

