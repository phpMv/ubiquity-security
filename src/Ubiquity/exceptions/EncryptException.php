<?php
namespace Ubiquity\exceptions;

/**
 * Encryption Exceptions
 *
 * @author jc
 *
 */
class EncryptException extends UbiquityException {

	public function __construct($message = null, $code = 0, $previous = null) {
		parent::__construct($message, $code, $previous);
	}
}
