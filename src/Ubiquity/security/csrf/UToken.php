<?php
namespace Ubiquity\security\csrf;

class UToken {

	/**
	 *
	 * @var string
	 */
	private $id;

	/**
	 *
	 * @var string
	 */
	private $value;

	public function __construct($id = null, $value = null) {
		$this->id = $id;
		$this->value = $value;
	}

	/**
	 *
	 * @return string
	 */
	public function getId() {
		return $this->id;
	}

	/**
	 *
	 * @return string
	 */
	public function getValue() {
		return $this->value;
	}

	/**
	 *
	 * @param string $id
	 */
	public function setId($id) {
		$this->id = $id;
	}

	/**
	 *
	 * @param string $value
	 */
	public function setValue($value) {
		$this->value = $value;
	}

	public function __toString() {
		return $this->value;
	}
}

