<?php
namespace Ubiquity\contents\transformation\transformers;

use Ubiquity\contents\transformation\TransformerInterface;
use Ubiquity\contents\transformation\TransformerViewInterface;
use Ubiquity\security\data\EncryptionManager;

class Crypt implements TransformerInterface,TransformerViewInterface {

	public static function transform($value) {
		return EncryptionManager::encrypt($value);
	}

	public static function reverse($value) {
		return EncryptionManager::decryptString($value);
	}

    public static function toView($value) {
        return EncryptionManager::decryptString($value);
    }
}
