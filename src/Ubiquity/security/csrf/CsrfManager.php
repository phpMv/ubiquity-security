<?php
namespace Ubiquity\security\csrf;

use Ubiquity\security\csrf\storages\TokenStorageInterface;
use Ubiquity\security\csrf\storages\SessionTokenStorage;
use Ubiquity\security\csrf\generators\Md5Selector;
use Ubiquity\security\csrf\generators\GeneratorInterface;
use Ubiquity\security\csrf\generators\RandomValidator;

/**
 * Ubiquity\security\csrf$CsrfManager
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class CsrfManager {

	/**
	 *
	 * @var GeneratorInterface
	 */
	private static $selector;

	/**
	 *
	 * @var GeneratorInterface
	 */
	private static $validator;

	/**
	 *
	 * @var TokenStorageInterface
	 */
	private static $storage;

	public static function start(TokenStorageInterface $storage = null, GeneratorInterface $selector = null, GeneratorInterface $validator = null) {
		self::$selector = $selector ?? new Md5Selector();
		self::$validator = $validator ?? new RandomValidator();
		self::$storage = $storage ?? new SessionTokenStorage();
	}

	/**
	 * Generates or retrieve and return a token.
	 *
	 * @param string $name
	 * @return \Ubiquity\security\csrf\UToken
	 */
	public static function getToken($name) {
		$id = self::$selector->generate($name);
		if (self::$storage->exists($id)) {
			$value = self::$storage->get($id);
		} else {
			$value = self::$validator->generate();
			self::$storage->set($id, $value);
		}
		return new UToken($id, $value);
	}

	/**
	 * Remove an existing token
	 *
	 * @param string $name
	 * @return ?string
	 */
	public static function removeToken(string $name): ?string {
		return self::$storage->remove(self::$selector->generate($name));
	}

	/**
	 * Returns whether the given CSRF token is valid, given his id.
	 *
	 * @param string $id
	 * @param string $value
	 * @return bool
	 */
	public static function isValid(string $id, string $value): bool {
		if (! self::$storage->exists($id)) {
			return false;
		}

		return hash_equals(self::$storage->get($id), $value);
	}

	/**
	 * Returns whether the given CSRF token is valid, given his name.
	 *
	 * @param string $name
	 * @param string $value
	 * @return bool
	 */
	public static function isValidByName(string $name, string $value): bool {
		return self::isValid(self::$selector->generate($name), $value);
	}

	/**
	 * Return a selector corresponding to a name, using the active selector.
	 *
	 * @param string $name
	 * @return string
	 */
	public static function getSelector(string $name): string {
		return self::$selector->generate($name);
	}

	/**
	 * Generates a token value using the active validator.
	 *
	 * @param string $value
	 * @return string
	 */
	public static function generateValue(?string $value = null): string {
		return self::$validator->generate($value);
	}

	public static function getValidatorClass(): string {
		return \get_class(self::$validator);
	}

	public static function getSelectorClass(): string {
		return \get_class(self::$selector);
	}

	public static function getStorageClass(): string {
		return \get_class(self::$storage);
	}

	public static function isStarted(): bool {
		return isset(self::$storage);
	}
}

