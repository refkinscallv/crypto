# Crypto Class Documentation

The `Crypto` class provides encryption and decryption functionalities with support for two storage methods: **local file storage** and **database storage**. Below is the complete guide for usage and configuration.

---

## Features

- **Customizable encryption key and cipher**
- **Local file storage with optional line limits**
- **Database storage with a user-defined handler**

---

## Usage Documentation

### Local File Storage

```php
<?php

use RF\Crypto\Crypto;

// Instantiate Crypto with local file storage
$crypt = new Crypto([
    "encryptKey" => "your-secret-key",
    "encryptFile" => "/path/to/encrypt.txt",
    "encryptLimitLine" => 5000,  // Optional: Max lines to keep in the file
    "encryptCipher" => "AES-256-CBC",  // Optional: Encryption cipher
    "encryptStoreMethod" => "local"  // Storage method
]);

// Encrypt data
$encryptedHash = $crypt->encrypt("Sensitive Data");
// $encryptedHash = $crypt->encrypt([1, 2, 3], "array"); if array

// Decrypt data
$decryptedData = $crypt->decrypt($encryptedHash);
// $decryptedData = $crypt->decrypt($encryptedHash, "array"); if array
```

### Database Storage

```php
<?php

use RF\Crypto\Crypto;

// Instantiate Crypto with database storage
$crypt = new Crypto([
    "encryptKey" => "your-secret-key",
    "encryptCipher" => "AES-256-CBC",  // Optional: Encryption cipher
    "encryptStoreMethod" => "database",  // Storage method
    "encryptDBHandler" => function($data, $mode) {
        global $db; // Assume $db is a database connection object

        if ($mode === "write") {
            // Insert encrypted data into the database
            $rawData = explode(":", $data);
            $query = "INSERT INTO table_encrypt (column_md5, column_actual_encrypt) VALUES (?, ?)";
            $stmt = $db->prepare($query);
            $stmt->execute([$rawData[1], $rawData[0]]);
            return $stmt->rowCount();
        } elseif ($mode === "read") {
            // Retrieve decrypted data from the database
            $query = "SELECT column_actual_encrypt FROM table_encrypt WHERE column_md5 = ? LIMIT 1";
            $stmt = $db->prepare($query);
            $stmt->execute([$data]);
            return $stmt->fetchColumn();
        }

        return false;
    }
]);

// Encrypt data
$encryptedHash = $crypt->encrypt("Sensitive Data");
// $encryptedHash = $crypt->encrypt([1, 2, 3], "array"); if array

// Decrypt data
$decryptedData = $crypt->decrypt($encryptedHash);
// $decryptedData = $crypt->decrypt($encryptedHash, "array"); if array
```

---

## API Reference

### `__construct(array $args)`

- **Description**: Initializes the `Crypto` object.
- **Parameters**:
  - `encryptKey` *(string)*: Secret key for encryption.
  - `encryptFile` *(string, optional)*: Path for file storage.
  - `encryptLimitLine` *(int, optional)*: Max lines for file storage.
  - `encryptCipher` *(string, optional)*: Encryption cipher (default: `AES-256-CBC`).
  - `encryptStoreMethod` *(string)*: Storage method, either `local` or `database`.
  - `encryptDBHandler` *(callable, optional)*: Function for database operations.
- **Throws**: `Exception` if configuration is invalid.

### `setFile(string $filePath): void`

- **Description**: Sets a custom file path.
- **Parameters**:
  - `$filePath` *(string)*: Path to the file.

### `encrypt(string|array $data, string $type = "string"): string|false`

- **Description**: Encrypts data.
- **Parameters**:
  - `$data` *(string|array)*: Data to be encrypted.
  - `$type` *(string)*: Type of data (`string` or `array`).
- **Returns**: MD5 hash of the encrypted data or `false` on failure.

### `decrypt(string $data, string $type = "string"): string|array|false`

- **Description**: Decrypts data.
- **Parameters**:
  - `$data` *(string)*: Data to be decrypted.
  - `$type` *(string)*: Type of data (`string` or `array`).
- **Returns**: Decrypted data or `false` on failure.

---

## Storage Methods

### Local File Storage

- Encrypts and stores data in a file.
- Automatically limits file size by removing older lines when `encryptLimitLine` is set.

### Database Storage

- Requires a user-defined `encryptDBHandler` function.
- Supports writing encrypted data and reading decrypted data directly from the database.

---

## Example Use Cases

- Encrypting sensitive data before storing in files or databases.
- Managing secure storage for web applications or APIs.

---

## Error Handling

The class throws exceptions for:
- Invalid configurations.
- Missing required options (e.g., `encryptKey`).
- Errors during encryption/decryption.

Handle errors using `try-catch` blocks:

```php
try {
    $crypt = new Crypto([...]);
    $encrypted = $crypt->encrypt("Sensitive Data");
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

---

## Contributions

Feel free to contribute to enhance the `Crypto` library. Fork the repository and submit pull requests!

---

## License

This library is open-source and licensed under the MIT License.