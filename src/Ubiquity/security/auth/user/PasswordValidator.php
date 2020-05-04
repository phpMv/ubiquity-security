<?php
namespace Ubiquity\security\auth\user;

use Ubiquity\contents\validation\validators\multiples\LengthValidator;

/**
 * Validates a password
 * Usage @validator("password","constraints"=>["min"=>v,"max"=>v,"upperCase"=>v,"numeric"=>v,"specialChar"=>v,"charser"=>v])
 * Ubiquity\security\auth\user$PasswordValidator
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class PasswordValidator extends LengthValidator {

	protected $min;

	protected $max;

	protected $upperCase;

	protected $numeric;

	protected $specialChar;

	protected $charset = "UTF-8";

	protected const PASSWORD_CONSTRAINTS = [
		'upperCase',
		'numeric',
		'specialChar'
	];

	public function __construct() {
		parent::__construct();
		$this->message = array_merge($this->message, [
			"min" => "This value cannot be longer than {max} characters",
			"exact" => "This value should have exactly {min} characters.",
			"charset" => "This value is not in {charset} charset",
			"upperCase" => "This value must contain at least {upperCase} uppercase characters",
			"numeric" => "This value must contain at least {numeric} numeric characters",
			"specialChar" => "This value must contain at least {specialChar} special characters"
		]);
	}

	protected function getCallables() {
		return [
			'upperCase' => function ($c) {
				return ctype_alpha($c) && strtoupper($c) === $c;
			},
			'numeric' => function ($c) {
				return is_numeric($c);
			},
			'specialChar' => function ($c) {
				return strpos($c, "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~") !== false;
			}
		];
	}

	protected function getLengths($string) {
		$result = array_combine(self::PASSWORD_CONSTRAINTS, array_fill(0, count(self::PASSWORD_CONSTRAINTS), 0));
		$size = strlen($string);
		for ($i = 0; $i < $size; $i ++) {
			$c = $string[$i];
			foreach ($this->getCallables() as $key => $callback) {
				if ($callback($c)) {
					$result[$key] ++;
				}
			}
		}
		return $result;
	}

	protected function validateValue($stringValue) {
		$result = parent::validateValue($stringValue);
		if (! $result) {
			return $result;
		}
		$lengths = $this->getLengths($stringValue);
		foreach (self::PASSWORD_CONSTRAINTS as $constraint) {
			if ($this->$constraint && $lengths[$constraint] < $this->$constraint) {
				$this->violation = $constraint;
				return false;
			}
		}
	}

	/**
	 *
	 * {@inheritdoc}
	 * @see \Ubiquity\contents\validation\validators\Validator::getParameters()
	 */
	public function getParameters(): array {
		return parent::getParameters() + self::PASSWORD_CONSTRAINTS;
	}
}

