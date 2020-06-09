<?php
namespace Ubiquity\exceptions;

/**
 * Encryption Exceptions
 *
 * @author jc
 *
 */
class EncryptException extends UbiquityException {

	public function __construct($message = null, $code = null, $previous = null) {
		parent::__construct($message, $code, $previous);
	}
}
