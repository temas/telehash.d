#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/ccm.h>
using CryptoPP::CTR_Mode;

#include <cryptopp/sha.h>
using CryptoPP::SHA;
using CryptoPP::SHA256;

#include <cryptopp/rsa.h>
using CryptoPP::RSAES;
using CryptoPP::RSASS;
using CryptoPP::OAEP;

#include <cryptopp/pssr.h>
using CryptoPP::PSS;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/filters.h>
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::ArraySink;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/files.h>
using CryptoPP::FileSource;

#include <cryptopp/base64.h>
using CryptoPP::Base64Decoder;

#include <cryptopp/asn.h>
using CryptoPP::OID;

#include <cryptopp/oids.h>

#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;

using CryptoPP::PKCS1v15;

struct RSAKeys {
  CryptoPP::RSA::PublicKey publicKey;
  CryptoPP::RSA::PrivateKey privateKey;
};

class RSA {
public:
  void rsa_sign() {
  }

  virtual size_t encryptLength(size_t plaintextLength) {
    RSAES< OAEP<SHA> >::Encryptor encryptor(keys.publicKey);
    return encryptor.CiphertextLength(plaintextLength);
  }

  virtual void encrypt(byte* plaintext, size_t plaintextLength, byte* cipherText) {
    RSAES< OAEP<SHA> >::Encryptor encryptor(keys.publicKey);
    AutoSeededRandomPool rng;

    encryptor.Encrypt(rng, plaintext, plaintextLength, cipherText);
  }

  virtual size_t decryptLength(size_t cipherTextLen) {
    RSAES< OAEP<SHA> >::Decryptor decryptor(keys.privateKey);
    return decryptor.MaxPlaintextLength(cipherTextLen);
  }

  virtual size_t decrypt(byte* cipherText, size_t cipherTextLen, byte* plaintext)  {
    RSAES< OAEP<SHA> >::Decryptor decryptor(keys.privateKey);
    AutoSeededRandomPool rng;

    DecodingResult result = decryptor.Decrypt(rng, cipherText, cipherTextLen, plaintext);
    return result.messageLength;
  }

  virtual size_t signatureLength() {
    RSASS<PKCS1v15, SHA256>::Signer signer(keys.privateKey);
    return signer.SignatureLength();
  }

  virtual size_t sign(byte* signingText, size_t signingTextLen, byte* signature) {
    RSASS<PKCS1v15, SHA256>::Signer signer(keys.privateKey);
    AutoSeededRandomPool rng;

    return signer.SignMessage(rng, signingText, signingTextLen, signature);
  }

  virtual bool verify(byte* message, size_t messageLength, byte* signature, size_t signatureLength) {
    RSASS<PKCS1v15, SHA256>::Verifier verifier(keys.publicKey);
    return verifier.VerifyMessage(message, messageLength, signature, signatureLength);
  }

  virtual size_t DERpublicKeyLength() {
    CryptoPP::ByteQueue bytes;
    keys.publicKey.DEREncode(bytes);
    return bytes.MaxRetrievable();
  }

  virtual void DERpublicKey(byte* publicKey, size_t publicKeyLength) {
    CryptoPP::ArraySink out(publicKey, publicKeyLength);
    keys.publicKey.DEREncode(out);
    out.MessageEnd();
  }

  void load_keys(const char* publicKeyFile, const char* privateKeyFile) {
    CryptoPP::ByteQueue bytes;

    CryptoPP::FileSource publicFS(publicKeyFile, true);
    publicFS.TransferTo(bytes);
    bytes.MessageEnd();
    keys.publicKey.Load(bytes);

    CryptoPP::FileSource privateFS(privateKeyFile, true);
    bytes.Clear();
    privateFS.TransferTo(bytes);
    bytes.MessageEnd();
    keys.privateKey.Load(bytes);

    AutoSeededRandomPool rng;
    if (!keys.publicKey.Validate(rng, 3)) {
      printf("Public key did not validate\n");
    }
    if (!keys.privateKey.Validate(rng, 3)) {
      printf("Private key did not validate\n");
    }
  }

  void set_public_key(byte* publicKey, size_t publicKeyLength) {
    CryptoPP::ByteQueue bytes;
    CryptoPP::StringSource inKey(publicKey, publicKeyLength, true);
    inKey.TransferTo(bytes);
    keys.publicKey.Load(bytes);

    AutoSeededRandomPool rng;
    if (!keys.publicKey.Validate(rng, 3)) {
      printf("Public key did not validate\n");
    }
  }

private:
  RSAKeys keys;
};

class ECDH {
public:
  ECDH() : domain(CryptoPP::ASN1::secp256r1()) {
  }

  ~ECDH() {
    printf("Cleanup\n");
    delete[] privateKey_;
    delete[] publicKey_;
  }

  virtual void generateKeys() {
    AutoSeededRandomPool rng;
    //domain.AccessGroupParameters().SetPointCompression(true);
    privateKey_ = new byte[domain.PrivateKeyLength()];
    publicKey_ = new byte[domain.PublicKeyLength()];
    domain.GenerateKeyPair(rng, privateKey_, publicKey_);
  }

  virtual size_t publicKeyLength() {
    return domain.PublicKeyLength();
  }

  virtual byte* publicKey() { return publicKey_; }

  virtual size_t agreedValueLength() {
    return domain.AgreedValueLength();
  }

  virtual void agree(byte* agreedValue, byte* remotePublicKey) {
    if (!domain.Agree(agreedValue, privateKey_, remotePublicKey)) {
      printf("Error agreeing\n");
    }
  }

private:
  CryptoPP::ECDH<ECP>::Domain domain;
  byte* privateKey_;
  byte* publicKey_;
};

extern "C" void aes_256_ctr_encrypt(byte* plaintext, int plaintext_len, byte* encrypted, byte* key, byte* iv) {
  CTR_Mode<AES>::Encryption aes;
  aes.SetKeyWithIV(key, 32, iv, 16);
  aes.ProcessData(encrypted, plaintext, plaintext_len);
}

extern "C" void aes_256_ctr_decrypt(byte* encrypted, int encrypted_len, byte* plaintext, byte* key, byte* iv) {
  CTR_Mode<AES>::Decryption aes;
  aes.SetKeyWithIV(key, 32, iv, 16);
  aes.ProcessData(plaintext, encrypted, encrypted_len);
}


RSA* rsa_load_keys(char* publicKeyFile, char* privateKeyFile) {
  RSA* result = new RSA;
  result->load_keys(publicKeyFile, privateKeyFile);
  return result;
}

extern "C" RSA* rsa_from_public(byte* publicKey, size_t publicKeyLength) {
  RSA* result = new RSA;
  try {
    result->set_public_key(publicKey, publicKeyLength);
  } catch (CryptoPP::Exception& e) {
    return 0;
  }
  return result;
}

ECDH* start_ecdh() {
  ECDH* result = new ECDH;
  result->generateKeys();
  return result;
}

extern "C" void sha256(byte* message, size_t message_len, byte* hash) {
  SHA256 sha;
  sha.Update(message, message_len);
  sha.Final(hash);
}

extern "C" void randomBytes(byte* dest, size_t length) {
  AutoSeededRandomPool rng;
  rng.GenerateBlock(dest, length);
}

