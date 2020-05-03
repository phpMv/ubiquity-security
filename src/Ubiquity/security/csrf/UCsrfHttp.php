<?php
namespace Ubiquity\security\csrf;

use Ubiquity\utils\http\UCookie;

/**
 * Ubiquity\security\csrf$UCsrfHttp
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class UCsrfHttp {

	/**
	 * Returns whether the given CSRF token is present and valid in POST values, given his name.
	 *
	 * @param string $name
	 * @return boolean
	 */
	public static function isValidPost(string $name): bool {
		$id = CsrfManager::getSelector($name);
		if (isset($_POST[$id])) {
			return CsrfManager::isValid($id, $_POST[$id]);
		}
		return false;
	}

	/**
	 * Returns whether the given CSRF token is present and valid in cookies, given his name.
	 *
	 * @param string $name
	 * @return bool
	 */
	public static function isValidCookie(string $name): bool {
		$id = CsrfManager::getSelector($name);
		$value = UCookie::get($id, null);
		if (isset($value)) {
			return CsrfManager::isValid($id, $value);
		}
		return false;
	}

	/**
	 * Adds a token in headers.
	 *
	 * @param string $name
	 */
	public static function getTokenMeta(string $name): string {
		$token = CsrfManager::getToken($name);
		return "<meta name='csrf-token' content='{$token->getId()}:{$token->getValue()}'>";
	}

	/**
	 * Returns an input field with a generated token
	 *
	 * @param string $name
	 * @return string
	 */
	public static function getTokenField(string $name): string {
		$token = CsrfManager::getToken($name);
		return "<input type='hidden' value='{$token->getValue()}' name='{$token->getId()}'>";
	}

	/**
	 * Adds a token in cookies.
	 *
	 * @param string $name
	 * @param string $path
	 * @param bool $secure
	 * @param bool $httpOnly
	 * @return bool
	 */
	public static function addCookieToken(string $name, string $path = '/', bool $secure = true, bool $httpOnly = true): bool {
		$token = CsrfManager::getToken($name);
		return UCookie::set($token->getId(), $token->getValue(), $path, $secure, $httpOnly);
	}
}

