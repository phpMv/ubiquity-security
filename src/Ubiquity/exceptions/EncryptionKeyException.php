<?php
namespace Ubiquity\exceptions;

/**
 * Decryption Exceptions
 *
 * @author jc
 *
 */
class EncryptionKeyException extends UbiquityException {

	public function __construct($message = null, $code = null, $previous = null) {
		parent::__construct($message, $code, $previous);
	}
}
