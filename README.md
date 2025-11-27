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
$valid  = Hash::verify_password( $password, $stored_hash );

// Data integrity
$hash      = Hash::data( [ 'user_id' => 123, 'action' => 'purchase' ] );
$file_hash = Hash::file( '/path/to/file.zip' );

// WordPress nonces
$nonce = Hash::nonce( 'delete_post_' . $post_id );
$valid = Hash::verify_nonce( $_POST['nonce'], 'delete_post_' . $post_id );

// HMAC authentication
$signature = Hash::hmac( $api_data, $secret_key );
$authentic = Hash::verify_hmac( $api_data, $signature, $secret_key );
```

## API

### Salt

#### `get_salt(): string`
Get combined WordPress salts for hashing.

### Password

#### `password( string $password ): string`
Hash passwords securely using WordPress methods.

#### `verify_password( string $password, string $hash ): bool`
Verify password against hash (timing-safe).

### Data

#### `data( mixed $data, string $algo = 'sha256', string $salt = '' ): ?string`
Hash any data (arrays, objects, strings). Uses WordPress salt by default. Returns null for invalid algorithms.

#### `file( string $path, string $algo = 'sha256' ): ?string`
Hash file contents. Returns null if file doesn't exist or isn't readable.

#### `attachment( int $id, string $algo = 'sha256' ): ?string`
Hash WordPress attachment file by ID.

#### `cache_key( mixed $data, string $prefix = '' ): string`
Generate cache keys from data: `Hash::cache_key( $query, 'posts' )` → `"posts_a1b2c3d4"`

### Nonce

#### `nonce( string $action ): string`
Create WordPress nonce for action verification.

#### `verify_nonce( string $nonce, string $action ): bool`
Verify WordPress nonce. Returns false for invalid/expired nonces.

### HMAC

#### `hmac( mixed $data, string $key = '', string $algo = 'sha256' ): ?string`
Generate HMAC for message authentication. Uses WordPress salt if key is empty.

#### `verify_hmac( mixed $data, string $expected, string $key = '', string $algo = 'sha256' ): bool`
Verify HMAC (timing-safe comparison).

## Common Use Cases
```php
// User authentication
$hashed = Hash::password( $user_password );
$valid  = Hash::verify_password( $input_password, $stored_hash );

// Form security
$nonce = Hash::nonce( 'update_profile' );
if ( Hash::verify_nonce( $_POST['nonce'], 'update_profile' ) ) {
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
if ( ! Hash::verify_nonce( $_POST['nonce'], 'delete_post' ) ) {
    wp_die( 'Security check failed' );
}

// ✅ Use verify_hmac() for timing-safe comparisons
$valid = Hash::verify_hmac( $data, $signature, $key );

// ❌ Never use == for signature comparison (timing attack risk)
// if ( Hash::hmac( $data, $key ) == $signature ) { }
```

## Supported Algorithms

- **SHA-256** (default, recommended)
- **SHA-1**, **MD5** (legacy support)
- **SHA-512** (high security)
- All PHP `hash_algos()` supported

## Requirements

- PHP 7.4+
- WordPress 5.0+

## License

GPL-2.0-or-later