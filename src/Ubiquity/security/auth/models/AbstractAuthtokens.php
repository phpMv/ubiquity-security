<?php
namespace Ubiquity\security\auth\models;

/**
 * Ubiquity\security\auth\models$AbstractAuthtokens
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
abstract class AbstractAuthtokens {

	/**
	 *
	 * @id
	 * @column("name"=>"id","nullable"=>false,"dbType"=>"int(11)")
	 * @validator("id","constraints"=>array("autoinc"=>true))
	 */
	protected $id;

	/**
	 *
	 * @column("name"=>"selector","nullable"=>false,"dbType"=>"char(24)")
	 * @validator("length","constraints"=>array("max"=>24,"notNull"=>true))
	 */
	protected $selector;

	/**
	 *
	 * @column("name"=>"hashedValidator","nullable"=>false,"dbType"=>"char(64)")
	 * @validator("length","constraints"=>array("max"=>64,"notNull"=>true))
	 */
	protected $hashedValidator;

	/**
	 *
	 * @column("name"=>"userid","nullable"=>false,"dbType"=>"int(11)")
	 * @validator("notNull")
	 */
	protected $userid;

	/**
	 *
	 * @column("name"=>"expires","nullable"=>true,"dbType"=>"datetime")
	 * @validator("type","dateTime")
	 * @transformer("datetime")
	 */
	protected $expires;

	public function __construct() {
		$this->selector = uniqid('', true);
		$this->hashedValidator = bin2hex(random_bytes(20));
		$this->setDuration('+1 day');
	}

	public function getId() {
		return $this->id;
	}

	public function setId($id) {
		$this->id = $id;
	}

	public function getSelector() {
		return $this->selector;
	}

	public function setSelector($selector) {
		$this->selector = $selector;
	}

	public function getHashedValidator() {
		return $this->hashedValidator;
	}

	public function setHashedValidator($hashedValidator) {
		$this->hashedValidator = $hashedValidator;
	}

	public function getUserid() {
		return $this->userid;
	}

	public function setUserid($userid) {
		$this->userid = $userid;
	}

	public function getExpires() {
		return $this->expires;
	}

	public function setExpires($expires) {
		$this->expires = $expires;
	}

	public function setDuration($duration) {
		$d = new \DateTime();
		$this->expires = $d->modify($duration);
	}

	public function isExpired() {
		return $this->expires->getTimestamp() < (new \DateTime())->getTimestamp();
	}

	public function checkValidator($validator) {
		return hash_equals($this->hashedValidator, $validator);
	}

	/**
	 *
	 * @return mixed
	 */
	abstract public function getUser();

	/**
	 *
	 * @param mixed $user
	 */
	abstract public function setUser($user);

	public function __toString() {
		return $this->selector . ':' . $this->hashedValidator;
	}
}