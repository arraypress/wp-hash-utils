<?php
/**
 * Hash Utilities
 *
 * This class provides essential hashing utilities for passwords, data integrity,
 * file verification, and WordPress security. Focuses on practical, frequently-used
 * operations with robust error handling and security best practices.
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
	 * Hash a password using WordPress's secure hashing.
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
	 * @param string $hash     Hashed password to verify against.
	 *
	 * @return bool True if password matches hash, false otherwise.
	 */
	public static function verify( string $password, string $hash ): bool {
		return wp_check_password( $password, $hash );
	}

	/**
	 * Hash data using specified algorithm.
	 *
	 * @param mixed  $data Data to hash (will be serialized if not string).
	 * @param string $algo Hashing algorithm (default: 'sha256').
	 *
	 * @return string|null Hash string or null if algorithm not supported.
	 */
	public static function data( mixed $data, string $algo = 'sha256' ): ?string {
		if ( ! in_array( $algo, hash_algos(), true ) ) {
			return null;
		}

		// Convert data to string if needed
		if ( ! is_string( $data ) ) {
			$data = maybe_serialize( $data );
		}

		return hash( $algo, $data );
	}

	/**
	 * Hash file contents.
	 *
	 * @param string $file_path Path to file.
	 * @param string $algo      Hashing algorithm (default: 'sha256').
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
	 * @return bool True if nonce is valid, false otherwise.
	 */
	public static function check_nonce( string $nonce, string $action ): bool {
		$result = wp_verify_nonce( $nonce, $action );

		return $result !== false && $result !== 0;
	}

	/**
	 * Generate HMAC (Hash-based Message Authentication Code).
	 *
	 * @param mixed  $data Data to authenticate.
	 * @param string $key  Secret key for HMAC.
	 * @param string $algo Hashing algorithm (default: 'sha256').
	 *
	 * @return string|null HMAC string or null if algorithm not supported.
	 */
	public static function hmac( mixed $data, string $key, string $algo = 'sha256' ): ?string {
		if ( ! in_array( $algo, hash_hmac_algos(), true ) ) {
			return null;
		}

		// Convert data to string if needed
		if ( ! is_string( $data ) ) {
			$data = maybe_serialize( $data );
		}

		return hash_hmac( $algo, $data, $key );
	}

	/**
	 * Verify HMAC authentication.
	 *
	 * @param mixed  $data     Original data.
	 * @param string $key      Secret key used for HMAC.
	 * @param string $expected Expected HMAC value.
	 * @param string $algo     Hashing algorithm (default: 'sha256').
	 *
	 * @return bool True if HMAC is valid, false otherwise.
	 */
	public static function verify_hmac( mixed $data, string $key, string $expected, string $algo = 'sha256' ): bool {
		$calculated = self::hmac( $data, $key, $algo );

		if ( $calculated === null ) {
			return false;
		}

		// Use hash_equals for timing-safe comparison
		return hash_equals( $expected, $calculated );
	}

	/**
	 * Generate cache key from data.
	 *
	 * @param mixed  $data   Data to generate cache key for.
	 * @param string $prefix Optional prefix for cache key.
	 *
	 * @return string Cache key.
	 */
	public static function cache_key( mixed $data, string $prefix = '' ): string {
		$hash = self::data( $data, 'md5' );

		return $prefix ? $prefix . '_' . $hash : $hash;
	}

	/**
	 * Hash WordPress attachment file.
	 *
	 * @param int    $attachment_id WordPress attachment ID.
	 * @param string $algo          Hashing algorithm (default: 'sha256').
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
	 * Generate multiple hashes for the same data.
	 *
	 * @param mixed $data  Data to hash.
	 * @param array $algos Array of algorithms to use (default: ['md5', 'sha1', 'sha256']).
	 *
	 * @return array Associative array of algorithm => hash pairs.
	 */
	public static function multi( mixed $data, array $algos = [ 'md5', 'sha1', 'sha256' ] ): array {
		$hashes = [];

		foreach ( $algos as $algo ) {
			$hash = self::data( $data, $algo );
			if ( $hash !== null ) {
				$hashes[ $algo ] = $hash;
			}
		}

		return $hashes;
	}

}