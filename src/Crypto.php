<?php

    namespace RF\Crypto;

    use Exception;

    /**
     * Class Crypto
     * Handles encryption and decryption of data with support for local file and database storage.
     *
     * @package RF\Crypto
     */
    class Crypto {

        /**
         * @var string Secret key for encryption.
         */
        private string $cryptSecretKey;

        /**
         * @var string|null Path to the local file for storage.
         */
        private ?string $cryptFile;

        /**
         * @var int Maximum number of lines to keep in the local file.
         */
        private int $cryptLimitLine;

        /**
         * @var string Encryption cipher to use.
         */
        private string $cryptCipherAlgo;

        /**
         * @var string Storage method, either 'local' or 'database'.
         */
        private string $cryptStoreMethod;

        /**
         * @var callable|null Closure function for database operations.
         */
        private $dbHandler;

        /**
         * Crypto constructor.
         * 
         * @param array $args Configuration settings.
         * 
         * @throws Exception if configuration is invalid.
         */
        public function __construct(array $args = []) {
            if (empty($args)) {
                throw new Exception("Invalid Crypto Config. Config can't be empty.");
                return;
            }

            $this->validationArgs($args);
        }

        /**
         * Validates and sets configuration arguments.
         * 
         * @param array $args Configuration settings.
         * 
         * @throws Exception if required settings are missing or invalid.
         */
        private function validationArgs(array $args): void {
            if (!isset($args["encryptKey"])) {
                throw new Exception("Invalid Crypto Config. array index 'encryptKey' not found.");
                return;
            }

            $this->cryptSecretKey = $args["encryptKey"];
            $this->cryptFile = isset($args["encryptFile"]) ? $_SERVER["DOCUMENT_ROOT"] . $args["encryptFile"] : null;
            $this->cryptLimitLine = isset($args["encryptLimitLine"]) ? $args["encryptLimitLine"] : 1000;
            $this->cryptCipherAlgo = isset($args["encryptCipher"]) ? $args["encryptCipher"] : "AES-256-CBC";
            $this->cryptStoreMethod = isset($args["encryptStoreMethod"]) ? $args["encryptStoreMethod"] : "local";
            $this->dbHandler = isset($args["encryptDBHandler"]) ? $args["encryptDBHandler"] : null;
            
            if ($this->cryptStoreMethod === 'local' && $this->cryptFile) {
                $defaultDir = dirname($this->cryptFile);
                if (!file_exists($defaultDir)) {
                    mkdir($defaultDir, 0777, true);
                }

                if (!file_exists($this->cryptFile)) {
                    file_put_contents($this->cryptFile, '');
                }
            } elseif ($this->cryptStoreMethod === 'database' && !$this->dbHandler) {
                throw new Exception("Database handler not provided for 'database' storage method.");
                return;
            }
        }

        /**
         * Sets a custom file path for local storage.
         * 
         * @param string $filePath Path to the file.
         */
        public function setFile(string $filePath): void {
            $this->cryptFile = $_SERVER["DOCUMENT_ROOT"] . $filePath;
        }

        /**
         * Encrypts the provided data.
         * 
         * @param string $data Data to be encrypted.
         * @param string $type Type of data ('string' or 'array'). Default is 'string'.
         * 
         * @return string|false MD5 hash of the encrypted data or false on failure.
         */
        public function encrypt(string $data, string $type = "string") {
            if (!$data) {
                return false;
            }

            if ($type === "array") {
                $data = @serialize($data);
            }

            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cryptCipherAlgo));
            $encryptedData = openssl_encrypt($data, $this->cryptCipherAlgo, $this->cryptSecretKey, 0, $iv);
            $base64Encoded = base64_encode($encryptedData . "::" . $iv);
            $md5hash = md5($base64Encoded);

            $this->translatingCrypto($base64Encoded . ":" . $md5hash, "write");

            return $md5hash;
        }

        /**
         * Decrypts the provided data.
         * 
         * @param string $data Encrypted data to be decrypted.
         * @param string $type Type of data ('string' or 'array'). Default is 'string'.
         * 
         * @return string|array|false Decrypted data or false on failure.
         */
        public function decrypt(string $data, string $type = "string") {
            if (!$data) {
                return false;
            }

            $data = $this->translatingCrypto($data, "read");

            list($encryptedData, $iv) = explode("::", base64_decode($data), 2) + [null, null];
            $decryptedData = openssl_decrypt($encryptedData, $this->cryptCipherAlgo, $this->cryptSecretKey, 0, $iv);

            if ($type === "array") {
                return @unserialize($decryptedData);
            } else {
                return $decryptedData;
            }
        }

        /**
         * Handles encryption and decryption operations based on storage method.
         * 
         * @param string $data Data to be processed.
         * @param string $mode Operation mode ('write' or 'read').
         * 
         * @return string|false Result of the operation or false on failure.
         */
        private function translatingCrypto(string $data, string $mode) {
            if ($this->cryptStoreMethod === 'local') {
                return $this->handleFileOperation($data, $mode);
            } elseif ($this->cryptStoreMethod === 'database' && $this->dbHandler) {
                return $this->handleDatabaseOperation($data, $mode);
            }

            return false;
        }

        /**
         * Handles file operations for encryption and decryption.
         * 
         * @param string $data Data to be processed.
         * @param string $mode Operation mode ('write' or 'read').
         * 
         * @return string|false Result of the operation or false on failure.
         */
        private function handleFileOperation(string $data, string $mode) {
            if ($mode === 'write') {
                $cryptoFile = fopen($this->cryptFile, "a");
                fwrite($cryptoFile, $data . PHP_EOL);
                fclose($cryptoFile);

                return $this->writeFile($this->cryptLimitLine);
            } elseif ($mode === 'read') {
                return $this->readFile($data);
            }

            return false;
        }

        /**
         * Handles database operations for encryption and decryption.
         * 
         * @param string $data Data to be processed.
         * @param string $mode Operation mode ('write' or 'read').
         * 
         * @return string|false Result of the operation or false on failure.
         */
        private function handleDatabaseOperation(string $data, string $mode) {
            if (!$this->dbHandler) {
                return false;
            }

            $dbOperation = $this->dbHandler;

            if ($mode === 'write') {
                return $dbOperation($data, 'write');
            } elseif ($mode === 'read') {
                return $dbOperation($data, 'read');
            }

            return false;
        }

        /**
         * Writes to the local file, maintaining a maximum number of lines.
         * 
         * @param int $limit Maximum number of lines to keep.
         */
        private function writeFile(int $limit): void {
            $fileContent = file($this->cryptFile);

            if (count($fileContent) > $limit) {
                $fileContent = array_slice($fileContent, -$limit);
                file_put_contents($this->cryptFile, implode("", $fileContent));
            }
        }

        /**
         * Reads from the local file and retrieves the data.
         * 
         * @param string $data Data to be retrieved.
         * 
         * @return string|false Retrieved data or false if not found.
         */
        private function readFile(string $data) {
            $fileContent = file($this->cryptFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

            foreach ($fileContent as $line) {
                $part = explode(":", $line);
                if (count($part) === 2 && $part[1] === $data) {
                    return $part[0];
                }
            }

            return false;
        }

    }
