# WordPress Hash Utils

A lean WordPress library for hashing, password security, data integrity, and verification.

## Installation

```bash
composer require arraypress/wp-hash-utils
```

## Quick Start

```php
use ArrayPress\HashUtils\Hash;

// Password security
$hashed = Hash::password( $password );
$valid  = Hash::verify( $password, $stored_hash );

// Data integrity
$hash      = Hash::data( [ 'user_id' => 123, 'action' => 'purchase' ] );
$file_hash = Hash::file( '/path/to/file.zip' );

// WordPress nonces
$nonce = Hash::nonce( 'delete_post_' . $post_id );
$valid = Hash::check_nonce( $_POST['nonce'], 'delete_post_' . $post_id );

// HMAC authentication
$signature = Hash::hmac( $api_data, $secret_key );
$authentic = Hash::verify_hmac( $api_data, $secret_key, $signature );
```

## API

### `password( string $password ): string`
Hash passwords securely using WordPress methods.

### `verify( string $password, string $hash ): bool`
Verify password against hash (timing-safe).

### `data( mixed $data, string $algo = 'sha256' ): ?string`
Hash any data (arrays, objects, strings). Returns null for invalid algorithms.

### `file( string $path, string $algo = 'sha256' ): ?string`
Hash file contents. Returns null if file doesn't exist or isn't readable.

### `nonce( string $action ): string`
Create WordPress nonce for action verification.

### `check_nonce( string $nonce, string $action ): bool`
Verify WordPress nonce. Returns false for invalid/expired nonces.

### `hmac( mixed $data, string $key, string $algo = 'sha256' ): ?string`
Generate HMAC for message authentication.

### `verify_hmac( mixed $data, string $key, string $expected, string $algo = 'sha256' ): bool`
Verify HMAC (timing-safe comparison).

### `cache_key( mixed $data, string $prefix = '' ): string`
Generate cache keys from data: `Hash::cache_key($query, 'posts')` → `"posts_a1b2c3d4"`

### `attachment( int $id, string $algo = 'sha256' ): ?string`
Hash WordPress attachment file by ID.

### `multi( mixed $data, array $algos = ['md5','sha1','sha256'] ): array`
Generate multiple hashes: `['md5' => '...', 'sha1' => '...', 'sha256' => '...']`

## Common Use Cases

```php
// User authentication
$hashed = Hash::password( $user_password );
$valid  = Hash::verify( $input_password, $stored_hash );

// Form security
$nonce = Hash::nonce( 'update_profile' );
if ( Hash::check_nonce( $_POST['nonce'], 'update_profile' ) ) {
	// Process form
}

// File integrity
$hash = Hash::file( $uploaded_file );
update_post_meta( $attachment_id, 'file_hash', $hash );

// API security
$signature = Hash::hmac( $request_data, $api_secret );
$headers   = [ 'X-Signature' => $signature ];

// Caching
$cache_key = Hash::cache_key( $complex_query_data, 'results' );
$cached    = get_transient( $cache_key );
```

## Security Best Practices

```php
// ✅ Always verify nonces for sensitive actions
if ( ! Hash::check_nonce( $_POST['nonce'], 'delete_post' ) ) {
	wp_die( 'Security check failed' );
}

// ✅ Use verify_hmac() for timing-safe comparisons
$valid = Hash::verify_hmac( $data, $key, $signature );

// ❌ Never use == for signature comparison (timing attack risk)
// if (Hash::hmac($data, $key) == $signature) { }
```

## Supported Algorithms

- **SHA-256** (default, recommended)
- **SHA-1**, **MD5** (legacy support)
- **SHA-512** (high security)
- All PHP `hash_algos()` supported

## Requirements

- PHP 7.4+
- WordPress 5.0+

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the GPL-2.0-or-later License.

## Support

- [Documentation](https://github.com/arraypress/wp-hash-utils)
- [Issue Tracker](https://github.com/arraypress/wp-hash-utils/issues)