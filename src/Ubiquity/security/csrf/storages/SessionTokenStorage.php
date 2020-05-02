<?php
namespace Ubiquity\security\csrf\storages;

use Ubiquity\utils\http\USession;

class SessionTokenStorage implements TokenStorageInterface {

	protected $key = '_CSRF';

	private $datas;

	protected function getKey($id) {
		return $this->key . '/' . $id;
	}

	public function __construct($key = '_CSRF') {
		$this->key = $key;
	}

	public function set($id, $token) {
		USession::set($this->getKey($id), $token);
	}

	public function get($id) {
		return USession::get($this->getKey($id));
	}

	public function exists($id) {
		return USession::exists($this->getKey($id));
	}

	public function remove($id) {
		return USession::delete($this->getKey($id));
	}
}

