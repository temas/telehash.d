module cryptopp;

extern (C++) {
  interface RSA {
    ulong encryptLength(ulong plaintextLength);
    bool encrypt(ubyte* plaintext, ulong plaintextLength, ubyte* ciphertext);
    ulong decryptLength(ulong ciphertextLength);
    ulong decrypt(ubyte* ciphertext, ulong ciphertextLength, ubyte* plaintext);
    ulong signatureLength();
    ulong sign(ubyte* signingText, ulong signingTextLen, ubyte* signature);
    bool verify(ubyte* message, ulong messageLength, ubyte* signature, ulong signatureLength);
    ulong DERpublicKeyLength();
    void DERpublicKey(ubyte* publicKey, ulong publicKeyLength);
  }
  
  RSA rsa_load_keys(immutable(char*)publicKeyFile, immutable(char*)privateKeyFile);

  interface ECDH {
    void generateKeys();
    ulong publicKeyLength();
    ubyte* publicKey();
    ulong agreedValueLength();
    void agree(ubyte* agreedValue, ubyte* remotePublicKey);
  }

  ECDH start_ecdh();
}

extern (C) {
  RSA rsa_from_public(ubyte* publicKey, ulong publicKeyLength);
  void sha256(ubyte* message, ulong messageLength, ubyte* hash);
  void aes_256_ctr_encrypt(ubyte* plaintext, ulong plaintext_len, ubyte* encrypted, ubyte* key, ubyte* iv);
  void aes_256_ctr_decrypt(ubyte* encrypted, ulong encrypted_len, ubyte* plaintext, ubyte* key, ubyte* iv);
}

