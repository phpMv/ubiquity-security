<?php
namespace Ubiquity\security\csrf\storages;

use Ubiquity\utils\http\USession;

class SessionTokenStorage implements TokenStorageInterface {

	protected $key = '_CSRF';

	protected function getKey($id) {
		return $this->key . '/' . $id;
	}

	public function __construct(string $key = '_CSRF') {
		$this->key = $key;
	}

	public function set(string $id, string $token): void {
		USession::set($this->getKey($id), $token);
	}

	public function get(string $id): ?string {
		return USession::get($this->getKey($id));
	}

	public function exists(string $id): bool {
		return USession::exists($this->getKey($id));
	}

	public function remove(string $id): ?string {
		$v = USession::get($id);
		USession::delete($this->getKey($id));
		return $v;
	}
}

