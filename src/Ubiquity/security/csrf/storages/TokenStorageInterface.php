<?php
namespace Ubiquity\security\csrf\storages;

interface TokenStorageInterface {

	/**
	 * Reads a stored CSRF token.
	 *
	 * @return string The stored token
	 *
	 */
	public function get(string $id): ?string;

	/**
	 * Stores a CSRF token.
	 */
	public function set(string $id, string $token): void;

	/**
	 * Removes a CSRF token.
	 *
	 * @return string|null Returns the removed token if one existed, NULL
	 *         otherwise
	 */
	public function remove(string $id): ?string;

	/**
	 * Checks whether a token with the given token ID exists.
	 *
	 * @return bool Whether a token exists with the given ID
	 */
	public function exists(string $id): bool;
}

