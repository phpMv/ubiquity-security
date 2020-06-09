<?php
namespace Ubiquity\security\data;

use Ubiquity\controllers\Startup;

/**
 * Ubiquity\security\data$EncryptionManager
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class EncryptionManager {

	const ENCRYPTION_KEY_NAME = 'encryption-key';

	/**
	 *
	 * @var Encryption
	 */
	private static $encryptionInstance;

	private static function getInstance(?string $key): Encryption {
		return self::$encryptionInstance ??= new Encryption($key);
	}

	private static function getEncryptionKey() {
		return Startup::$config[self::ENCRYPTION_KEY_NAME] ?? null;
	}

	/**
	 * Start the manager and eventually generate the encryption key.
	 * Do not use in production
	 *
	 * @param array $config
	 */
	public static function start(array &$config) {
		$oldKey = $config[self::ENCRYPTION_KEY_NAME] ?? null;
		self::getInstance($oldKey);
		$key = self::$encryptionInstance->getKey();

		if ($oldKey !== $key) {
			$config[self::ENCRYPTION_KEY_NAME] = $key;
			Startup::saveConfig($config);
		}
	}

	/**
	 * Start the encryption manager for production.
	 *
	 * @param array $config
	 */
	public static function startProd(array &$config) {
		self::getInstance($config[self::ENCRYPTION_KEY_NAME] ?? null);
	}

	/**
	 * Encrypt the given data.
	 *
	 * @param mixed $data
	 * @return string
	 */
	public static function encrypt($data): string {
		if (is_string($data)) {
			return self::$encryptionInstance->encryptString($data);
		}
		return self::$encryptionInstance->encrypt($data);
	}

	/**
	 * Decrypt the given string.
	 *
	 * @param string $data
	 * @return string
	 */
	public static function decryptString(string $data): string {
		return self::$encryptionInstance->decryptString($data);
	}

	/**
	 * Decrypt the given data with possible unserialization.
	 *
	 * @param string $data
	 * @param boolean $unserialize
	 * @return mixed|string
	 */
	public static function decrypt(string $data, $unserialize = true) {
		return self::$encryptionInstance->decrypt($data, $unserialize);
	}

	/**
	 * Generate a new encryption key.
	 *
	 * @param string $cipher
	 * @return string
	 */
	public static function generateKey(?string $cipher = Encryption::AES128): string {
		return self::getInstance(null)->generateKey($cipher);
	}

	public static function getKey() {
		return self::getInstance(self::getKey())->getKey();
	}
}

