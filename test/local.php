<?php

    use RF\Crypto\Crypto;

    require "../vendor/autoload.php";

    $crypt = new Crypto([
        "encryptKey" => "your-secret-key",
        "encryptFile" => "/writeable/encrypt.txt",
        "encryptLimitLine" => 5000,
        "encryptCipher" => "AES-256-CBC",
        "encryptStoreMethod" => "local"
    ]);
    
    // Set a custom file path
    // $crypt->setFile("/writeable/other-file.txt");

    // Encrypt data
    $encryptedHash = $crypt->encrypt(rand(1,999999999999) ." - ". date("Y-m-d H:i:s"));

    // Decrypt data
    $decryptedData = $crypt->decrypt($encryptedHash);

    echo $decryptedData;