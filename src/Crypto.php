<?php

    namespace RF\Security;

    use Exception;

    /**
     * Class Crypto
     *
     * A class for encrypting and decrypting data with support for file-based or database-based storage.
     */
    class Crypto
    {

        private string $cryptSecretKey;
        private string $cryptFile;
        private int $cryptLimitLine;
        private string $cryptCipherAlgo;
        private string $cryptStoreMethod;
        private $dbhandler;

        /**
         * Crypto constructor.
         *
         * @param callable|null $db A database handler callback for database operations.
         * @throws Exception
         */
        public function __construct($db = null)
        {
            $this->cryptSecretKey = $_SERVER["ENCRYPT_KEY"] ?? throw new Exception("Encryption key is not defined.");
            $this->cryptFile = $_SERVER["DOCUMENT_ROOT"] . '/' . ($_SERVER["ENCRYPT_FILE"] ?? 'crypto_storage.txt');
            $this->cryptLimitLine = (int)($_SERVER["ENCRYPT_LIMIT"] ?? 1000);
            $this->cryptCipherAlgo = $_SERVER["ENCRYPT_CIPHER"] ?? "AES-256-CBC";
            $this->cryptStoreMethod = $_SERVER["ENCRYPT_STORE"] ?? "local";
            $this->dbhandler = $db;

            $this->initializeStorage();
        }

        /**
         * Initialize the storage system (local file or database).
         *
         * @throws Exception If storage method is "database" but no database handler is provided.
         */
        private function initializeStorage(): void
        {
            if ($this->cryptStoreMethod === "local" && $this->cryptFile) {
                $defaultDir = dirname($this->cryptFile);
                if (!is_dir($defaultDir) && !mkdir($defaultDir, 0777, true) && !is_dir($defaultDir)) {
                    throw new Exception("Failed to create directory: $defaultDir");
                }

                if (!file_exists($this->cryptFile) && file_put_contents($this->cryptFile, "") === false) {
                    throw new Exception("Failed to create storage file: $this->cryptFile");
                }
            } elseif ($this->cryptStoreMethod === "database" && !$this->dbhandler) {
                throw new Exception("Database handler not provided for 'database' storage method.");
            }
        }

        /**
         * Set the file path for local storage.
         *
         * @param string $filePath The relative file path.
         */
        public function setFile(string $filePath): void
        {
            $this->cryptFile = $_SERVER["DOCUMENT_ROOT"] . '/' . ltrim($filePath, '/');
        }

        /**
         * Encrypt data.
         *
         * @param mixed $data The data to encrypt.
         * @param string $type The data type ("string" or "array").
         * @return string|false The MD5 hash of the encrypted data, or false on failure.
         */
        public function encrypt(mixed $data, string $type = "string"): string|false
        {
            if (empty($data)) {
                return false;
            }

            if ($type === "array") {
                $data = serialize($data);
            }

            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cryptCipherAlgo));
            $encryptedData = openssl_encrypt($data, $this->cryptCipherAlgo, $this->cryptSecretKey, 0, $iv);

            if ($encryptedData === false) {
                throw new Exception("Failed to encrypt data.");
            }

            $base64Encoded = base64_encode($encryptedData . "::" . $iv);
            $md5hash = md5($base64Encoded);

            $this->translatingCrypto($base64Encoded . ":" . $md5hash, "write");

            return $md5hash;
        }

        /**
         * Decrypt data.
         *
         * @param string $data The data to decrypt.
         * @param string $type The data type ("string" or "array").
         * @return mixed The decrypted data, or false on failure.
         */
        public function decrypt(string $data, string $type = "string"): mixed
        {
            if (empty($data)) {
                return false;
            }

            $storedData = $this->translatingCrypto($data, "read");
            $decodedData = explode("::", base64_decode($storedData), 2);

            if (count($decodedData) !== 2) {
                return false;
            }

            [$encryptedData, $iv] = $decodedData;

            $decryptedData = openssl_decrypt($encryptedData, $this->cryptCipherAlgo, $this->cryptSecretKey, 0, $iv);

            if ($decryptedData === false) {
                throw new Exception("Failed to decrypt data.");
            }

            return $type === "array" ? unserialize($decryptedData) : $decryptedData;
        }

        /**
         * Handle translation between storage and data.
         *
         * @param string $data The data to write or read.
         * @param string $mode The mode ("write" or "read").
         * @return mixed The result of the operation.
         */
        private function translatingCrypto(string $data, string $mode): mixed
        {
            return $this->cryptStoreMethod === "local"
                ? $this->handleFileOperation($data, $mode)
                : $this->handleDatabaseOperation($data, $mode);
        }

        /**
         * Handle file-based operations.
         *
         * @param string $data The data to write or read.
         * @param string $mode The mode ("write" or "read").
         * @return mixed The result of the operation.
         */
        private function handleFileOperation(string $data, string $mode): mixed
        {
            if ($mode === "write") {
                if (file_put_contents($this->cryptFile, $data . PHP_EOL, FILE_APPEND) === false) {
                    throw new Exception("Failed to write to storage file: $this->cryptFile");
                }
                $this->enforceFileLimit($this->cryptLimitLine);
                return true;
            } elseif ($mode === "read") {
                return $this->readFile($data);
            }

            return false;
        }

        /**
         * Enforce file size limit.
         *
         * @param int $limit The maximum number of lines to retain.
         */
        private function enforceFileLimit(int $limit): void
        {
            $fileContent = file($this->cryptFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

            if ($fileContent === false) {
                throw new Exception("Failed to read storage file: $this->cryptFile");
            }

            if (count($fileContent) > $limit) {
                $fileContent = array_slice($fileContent, -$limit);
                file_put_contents($this->cryptFile, implode(PHP_EOL, $fileContent));
            }
        }

        /**
         * Read a specific data entry from the file.
         *
         * @param string $data The data to search for.
         * @return string|false The corresponding stored data, or false if not found.
         */
        private function readFile(string $data): string|false
        {
            $fileContent = file($this->cryptFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

            if ($fileContent === false) {
                throw new Exception("Failed to read storage file: $this->cryptFile");
            }

            foreach ($fileContent as $line) {
                [$storedData, $hash] = explode(":", $line);
                if ($hash === $data) {
                    return $storedData;
                }
            }

            return false;
        }

        /**
         * Handle database-based operations.
         *
         * @param string $data The data to write or read.
         * @param string $mode The mode ("write" or "read").
         * @return mixed The result of the database operation.
         */
        private function handleDatabaseOperation(string $data, string $mode): mixed
        {
            if (!$this->dbhandler) {
                throw new Exception("Database handler not provided.");
            }

            return $mode === "write" 
                ? ($this->dbhandler)($data, "write") 
                : ($this->dbhandler)($data, "read");
        }
        
    }
