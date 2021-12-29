<?php
namespace Ubiquity\security\csp;

/**
 * Ubiquity\security\csp$CspValues
 * This class is part of Ubiquity
 *
 * @author jc
 * @version 1.0.0
 *
 */
class CspValues {

	const ALL = '*';

	const NONE = 'none';

	const DATA = 'data:';

	const HTTPS = 'https:';

	const SELF = 'self';

	const UNSAFE_INLINE = 'unsafe-inline';

	const STRICT_DYNAMIC = 'strict-dynamic';

	const UNSAFE_HASHES = 'unsafe-hashes';

	const QUOTED = [
		self::NONE,
		self::SELF,
		self::UNSAFE_INLINE,
		self::STRICT_DYNAMIC,
		self::UNSAFE_HASHES
	];
}
