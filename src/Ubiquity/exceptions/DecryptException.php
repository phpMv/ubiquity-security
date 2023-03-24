<?php
namespace Ubiquity\exceptions;

/**
 * Decryption Exceptions
 *
 * @author jc
 *
 */
class DecryptException extends UbiquityException {

	public function __construct($message = null, $code = 0, $previous = null) {
		parent::__construct($message, $code, $previous);
	}
}
