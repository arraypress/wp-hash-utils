<?php
/**
 * Hash Utilities
 *
 * Provides hashing utilities for data integrity, verification, and security.
 * Requires WordPress environment.
 *
 * @package ArrayPress\HashUtils
 * @since   1.0.0
 * @author  ArrayPress
 * @license GPL-2.0-or-later
 */

declare( strict_types=1 );

namespace ArrayPress\HashUtils;

class Hash {

	/**
	 * Get WordPress salt for hashing.
	 *
	 * @return string Combined WordPress salts.
	 */
	public static function get_salt(): string {
		return wp_salt() . wp_salt( 'secure_auth' ) . wp_salt( 'logged_in' ) . wp_salt( 'nonce' );
	}

	/**
	 * Hash data using specified algorithm.
	 *
	 * @param mixed  $data Data to hash (will be serialized if not string).
	 * @param string $algo Hashing algorithm.
	 * @param string $salt Optional custom salt. Uses WordPress salt if empty.
	 *
	 * @return string|null Hash string or null if algorithm not supported.
	 */
	public static function data( $data, string $algo = 'sha256', string $salt = '' ): ?string {
		if ( ! in_array( $algo, hash_algos(), true ) ) {
			return null;
		}

		if ( ! is_string( $data ) ) {
			$data = maybe_serialize( $data );
		}

		if ( empty( $salt ) ) {
			$salt = self::get_salt();
		}

		return hash( $algo, $data . $salt );
	}

	/**
	 * Hash file contents.
	 *
	 * @param string $file_path Path to file.
	 * @param string $algo      Hashing algorithm.
	 *
	 * @return string|null File hash or null on failure.
	 */
	public static function file( string $file_path, string $algo = 'sha256' ): ?string {
		if ( ! file_exists( $file_path ) || ! is_readable( $file_path ) ) {
			return null;
		}

		if ( ! in_array( $algo, hash_algos(), true ) ) {
			return null;
		}

		$hash = hash_file( $algo, $file_path );

		return $hash !== false ? $hash : null;
	}

	/**
	 * Hash WordPress attachment file.
	 *
	 * @param int    $attachment_id WordPress attachment ID.
	 * @param string $algo          Hashing algorithm.
	 *
	 * @return string|null Attachment file hash or null on failure.
	 */
	public static function attachment( int $attachment_id, string $algo = 'sha256' ): ?string {
		$file_path = get_attached_file( $attachment_id );

		if ( ! $file_path ) {
			return null;
		}

		return self::file( $file_path, $algo );
	}

	/**
	 * Generate HMAC (Hash-based Message Authentication Code).
	 *
	 * @param mixed  $data Data to authenticate.
	 * @param string $key  Secret key. Uses WordPress salt if empty.
	 * @param string $algo Hashing algorithm.
	 *
	 * @return string|null HMAC string or null if algorithm not supported.
	 */
	public static function hmac( $data, string $key = '', string $algo = 'sha256' ): ?string {
		if ( ! in_array( $algo, hash_hmac_algos(), true ) ) {
			return null;
		}

		if ( ! is_string( $data ) ) {
			$data = maybe_serialize( $data );
		}

		if ( empty( $key ) ) {
			$key = self::get_salt();
		}

		return hash_hmac( $algo, $data, $key );
	}

	/**
	 * Verify HMAC authentication.
	 *
	 * @param mixed  $data     Original data.
	 * @param string $expected Expected HMAC value.
	 * @param string $key      Secret key. Uses WordPress salt if empty.
	 * @param string $algo     Hashing algorithm.
	 *
	 * @return bool True if HMAC is valid.
	 */
	public static function verify_hmac( $data, string $expected, string $key = '', string $algo = 'sha256' ): bool {
		$calculated = self::hmac( $data, $key, $algo );

		if ( $calculated === null ) {
			return false;
		}

		return hash_equals( $expected, $calculated );
	}

	/**
	 * Hash a password securely.
	 *
	 * @param string $password Password to hash.
	 *
	 * @return string Hashed password.
	 */
	public static function password( string $password ): string {
		return wp_hash_password( $password );
	}

	/**
	 * Verify a password against its hash.
	 *
	 * @param string $password Plain text password.
	 * @param string $hash     Hashed password.
	 *
	 * @return bool True if password matches.
	 */
	public static function verify_password( string $password, string $hash ): bool {
		return wp_check_password( $password, $hash );
	}

	/**
	 * Create WordPress nonce for action verification.
	 *
	 * @param string $action Action to create nonce for.
	 *
	 * @return string Nonce string.
	 */
	public static function nonce( string $action ): string {
		return wp_create_nonce( $action );
	}

	/**
	 * Verify WordPress nonce.
	 *
	 * @param string $nonce  Nonce to verify.
	 * @param string $action Action the nonce was created for.
	 *
	 * @return bool True if nonce is valid.
	 */
	public static function verify_nonce( string $nonce, string $action ): bool {
		$result = wp_verify_nonce( $nonce, $action );

		return $result !== false && $result !== 0;
	}

	/**
	 * Generate cache key from data.
	 *
	 * @param mixed  $data   Data to generate cache key for.
	 * @param string $prefix Optional prefix.
	 *
	 * @return string Cache key.
	 */
	public static function cache_key( $data, string $prefix = '' ): string {
		if ( ! is_string( $data ) ) {
			$data = maybe_serialize( $data );
		}

		$hash = md5( $data );

		return $prefix !== '' ? $prefix . '_' . $hash : $hash;
	}

}