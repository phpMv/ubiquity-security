<?php
namespace Ubiquity\security\data;

use Ubiquity\exceptions\EncryptException;
use Ubiquity\exceptions\DecryptException;

/**
 * Ubiquity\security\data$Encryption
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class Encryption {

	const AES128 = 'AES-128-CBC';

	const AES256 = 'AES-256-CBC';

	/**
	 * The encryption key.
	 *
	 * @var string
	 */
	protected $key;

	/**
	 * The algorithm used for encryption.
	 *
	 * @var string
	 */
	protected $cipher;

	/**
	 * Create a new encrypter instance.
	 *
	 * @param string $key
	 * @param string $cipher
	 * @return void
	 *
	 * @throws \RuntimeException
	 */
	public function __construct(?string $key = null, ?string $cipher = self::AES128) {
		$this->key = (isset($key)) ? (string) $key : self::generateKey($cipher);
		$this->cipher = $cipher;
	}

	/**
	 * Create a MAC for the given value.
	 *
	 * @param string $iv
	 * @param mixed $value
	 * @return string
	 */
	protected function hash($iv, $value): string {
		return \hash_hmac('sha256', $iv . $value, $this->key);
	}

	/**
	 * Get the JSON array from the given payload.
	 *
	 * @param string $payload
	 * @return array
	 */
	protected function getJsonPayload($payload) {
		$payload = \json_decode(\base64_decode($payload), true);
		if (! $this->isValidPayload($payload)) {
			throw new DecryptException('The payload is invalid.');
		}
		if (! $this->isValidMac($payload)) {
			throw new DecryptException('The MAC control is invalid.');
		}

		return $payload;
	}

	/**
	 * Check that the encryption payload is valid.
	 *
	 * @param mixed $payload
	 * @return bool
	 */
	protected function isValidPayload($payload) {
		return \is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']) && \strlen(\base64_decode($payload['iv'], true)) === \openssl_cipher_iv_length($this->cipher);
	}

	/**
	 * Check if the MAC for the given payload is valid.
	 *
	 * @param array $payload
	 * @return bool
	 */
	protected function isValidMac(array $payload) {
		$calculated = $this->calculateMac($payload, $bytes = random_bytes(16));
		return \hash_equals(\hash_hmac('sha256', $payload['mac'], $bytes, true), $calculated);
	}

	/**
	 * Calculate the hash of the given payload.
	 *
	 * @param array $payload
	 * @param string $bytes
	 * @return string
	 */
	protected function calculateMac($payload, $bytes) {
		return \hash_hmac('sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true);
	}

	/**
	 * Encrypt the given value.
	 *
	 * @param mixed $value
	 * @param bool $serialize
	 * @return string
	 *
	 */
	public function encrypt($value, $serialize = true): string {
		$iv = \random_bytes(\openssl_cipher_iv_length($this->cipher));
		$value = \openssl_encrypt($serialize ? \serialize($value) : $value, $this->cipher, $this->key, 0, $iv);
		if ($value === false) {
			throw new EncryptException('Could not encrypt the data with openssl.');
		}

		$mac = $this->hash($iv = base64_encode($iv), $value);
		$json = \json_encode(\compact('iv', 'value', 'mac'), JSON_UNESCAPED_SLASHES);
		if (\json_last_error() !== \JSON_ERROR_NONE) {
			throw new EncryptException('Could not json_encode the data.');
		}

		return \base64_encode($json);
	}

	/**
	 * Encrypt a string without serialization.
	 *
	 * @param string $value
	 * @return string
	 */
	public function encryptString(string $value): string {
		return $this->encrypt($value, false);
	}

	/**
	 * Decrypt the given value.
	 *
	 * @param string $payload
	 * @param bool $unserialize
	 * @return mixed
	 *
	 */
	public function decrypt(string $payload, $unserialize = true) {
		$payload = $this->getJsonPayload($payload);
		$iv = base64_decode($payload['iv']);
		$decrypted = \openssl_decrypt($payload['value'], $this->cipher, $this->key, 0, $iv);

		if ($decrypted === false) {
			throw new DecryptException('Could not decrypt the data.');
		}

		return $unserialize ? unserialize($decrypted) : $decrypted;
	}

	/**
	 * Decrypt the given string without unserialization.
	 *
	 * @param string $payload
	 * @return string
	 *
	 */
	public function decryptString($payload) {
		return $this->decrypt($payload, false);
	}

	/**
	 * Check if the given key and cipher combination is valid.
	 *
	 * @param string $key
	 * @param string $cipher
	 * @return bool
	 */
	public static function isValidKey(string $key, string $cipher): bool {
		$length = \mb_strlen($key, '8bit');
		return ($cipher === self::AES128 && $length === 16) || ($cipher === self::AES256 && $length === 32);
	}

	/**
	 * Generate a new key for the given cipher.
	 *
	 * @param string $cipher
	 * @return string
	 */
	public static function generateKey(string $cipher): string {
		return \bin2hex(\random_bytes($cipher === self::AES128 ? 16 : 32));
	}

	/**
	 *
	 * @return string
	 */
	public function getKey() {
		return $this->key;
	}

	/**
	 *
	 * @return string
	 */
	public function getCipher() {
		return $this->cipher;
	}
}

