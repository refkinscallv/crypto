<?php

    use RF\Crypto\Crypto;

    require "../vendor/autoload.php";

    $db = new mysqli("localhost", "root", "", "cg");

    // Instantiate Crypto with database storage
    $crypt = new Crypto([
        "encryptKey" => "your-secret-key",
        "encryptCipher" => "AES-256-CBC",  // Optional: Encryption cipher
        "encryptStoreMethod" => "database",  // Storage method
        "encryptDBHandler" => function($data, $mode) use ($db) {
            if ($mode === "write") {
                // Example: Insert encrypted data into the database
                $rawData = explode(":", $data);
                $query = "INSERT INTO crypto (md5Data, actualData) VALUES (?, ?)";
                $stmt = $db->prepare($query);
                $stmt->bind_param("ss", $rawData[1], $rawData[0]);
                $stmt->execute();
    
                // Check the number of affected rows
                return $db->affected_rows;
            } elseif ($mode === "read") {
                // Example: Retrieve decrypted data from the database
                $query = "SELECT actualData FROM crypto WHERE md5Data = ? LIMIT 1";
                $stmt = $db->prepare($query);
                $stmt->bind_param("s", $data);
                $stmt->execute();
                $stmt->bind_result($result);
                $stmt->fetch();
                return $result ? $result : false;
            }
    
            return false;
        }
    ]);

    // Encrypt data
    $encryptedHash = $crypt->encrypt(rand(1,999999999999) ." - ". date("Y-m-d H:i:s"));

    // Decrypt data
    $decryptedData = $crypt->decrypt($encryptedHash);

    echo $decryptedData;