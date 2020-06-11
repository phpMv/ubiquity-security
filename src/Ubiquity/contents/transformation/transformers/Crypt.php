<?php
namespace Ubiquity\contents\transformation\transformers;

use Ubiquity\contents\transformation\TransformerInterface;
use Ubiquity\security\data\EncryptionManager;

class Crypt implements TransformerInterface {

	public static function transform($value) {
		return EncryptionManager::encrypt($value);
	}

	public static function reverse($value) {
		return EncryptionManager::decryptString($value);
	}
}