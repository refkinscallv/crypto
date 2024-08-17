## Usage Documentation

The `Crypto` class provides encryption and decryption functionalities with support for two storage methods: local file storage and database storage. This documentation explains how to use the `Crypto` class and customize its configuration.

### Basic Usage

#### Local File Storage

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

// Decrypt data
$decryptedData = $crypt->decrypt($encryptedHash);

// Set a custom file path
$crypt->setFile("/path/to/anotherFile.txt");

?>
```

#### Database Storage

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
            // Example: Insert encrypted data into the database
            $rawData = explode(":", $data);
            $query = "INSERT INTO table_encrypt (column_md5, column_actual_encrypt) VALUES (?, ?)";
            $stmt = $db->prepare($query);
            $stmt->execute([$rawData[1], $rawData[0]]);
            return $stmt->rowCount();
        } elseif ($mode === "read") {
            // Example: Retrieve decrypted data from the database
            $query = "SELECT column_actual_encrypt FROM table_encrypt WHERE column_md5 = ? LIMIT 1";
            $stmt = $db->prepare($query);
            $stmt->execute([$data]);
            $result = $stmt->fetchColumn();
            return $result ? $result : false;
        }

        return false;
    }
]);

// Encrypt data
$encryptedHash = $crypt->encrypt("Sensitive Data");

// Decrypt data
$decryptedData = $crypt->decrypt($encryptedHash);

?>
```

### Class Methods

#### `__construct(array $args)`

Constructor method to initialize the `Crypto` object with configuration settings.

- **Parameters:**
  - `array $args`: Configuration array with keys:
    - `encryptKey` (string): Secret key for encryption.
    - `encryptFile` (string, optional): Path to the local file for storage.
    - `encryptLimitLine` (int, optional): Maximum number of lines to keep in the local file.
    - `encryptCipher` (string, optional): Encryption cipher to use.
    - `encryptStoreMethod` (string, optional): Storage method, either 'local' or 'database'.
    - `encryptDBHandler` (callable, optional): Closure function for database operations (required if using 'database').

- **Throws:**
  - `Exception` if configuration is invalid or required fields are missing.

#### `setFile(string $filePath): void`

Sets a custom file path for local storage.

- **Parameters:**
  - `string $filePath`: Path to the file.

#### `encrypt(string $data, string $type = "string")`

Encrypts the provided data.

- **Parameters:**
  - `string $data`: Data to be encrypted.
  - `string $type`: Type of data ('string' or 'array'). Default is 'string'.
- **Returns:**
  - `string|false`: MD5 hash of the encrypted data or `false` on failure.

#### `decrypt(string $data, string $type = "string")`

Decrypts the provided data.

- **Parameters:**
  - `string $data`: Encrypted data to be decrypted.
  - `string $type`: Type of data ('string' or 'array'). Default is 'string'.
- **Returns:**
  - `string|array|false`: Decrypted data or `false` on failure.

### Storage Methods

#### Local File Storage

The local file storage method writes encrypted data to a specified file and handles file management such as maintaining a maximum number of lines.

#### Database Storage

The database storage method uses a custom closure to handle data operations with the database. The closure must accept two parameters: `$data` (data to be processed) and `$mode` (either 'write' or 'read').