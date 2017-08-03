require "CryptoSupport/handlers/rsa_complex_bypass_handler.h";
require "openssl/pem.h", "openssl/bn.h", "openssl/bio.h";
require "openssl/evp.h";
require "CryptoSupport/primitives/asymmetricPrimitives.chpl";

module rsaSupport {

  use CryptoUtils;
  use CryptoUtils;
  use asymmetricPrimitives;
  use asymmetricPrimitives;


  proc generateKeys() {
    var keyLen: c_int = 2048;
    var e = RSA_F4;

    var bne = BN_new();
    var rsa = RSA_new();

    var ret = BN_set_word(bne, e);
    ret = RSA_generate_key_ex(rsa, keyLen: c_int, bne, c_nil: BN_GENCB_PTR);

    var bp_public = BIO_new_file("public.pem".c_str(), "w+".c_str());
    ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);

    var bp_private = BIO_new_file("private.pem".c_str(), "w+".c_str());
    ret = PEM_write_bio_RSAPrivateKey(bp_private,
                                      rsa,
                                      c_nil: EVP_CIPHER_PTR,
                                      c_nil: c_ptr(c_uchar),
                                      0: c_int,
                                      c_nil: PEM_PWD_CB_PTR,
                                      c_nil: c_void_ptr);
    writeln(ret);
  }
}


proc main() {
  use rsaSupport;
  use rsaSupport;
  generateKeys();
}



/*#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

int main() {
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    char   msg[KEY_LENGTH/8];  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages
//Generate key pair
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

// To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);
    pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    #ifdef PRINT_KEYS
        printf("\n%s\n%s\n", pri_key, pub_key);
    #endif
    printf("done.\n");

// Get the message to encrypt
    printf("Message to encrypt: ");
    fgets(msg, KEY_LENGTH-1, stdin);
    msg[strlen(msg)-1] = '\0';

// Encrypt the message
    encrypt = (char*)malloc(RSA_size(keypair));
    int encrypt_len;
    err = (char*)malloc(130);
    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        goto free_stuff;
    }

// Decrypt it
decrypt = (char*)malloc(encrypt_len);
if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt, keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    fprintf(stderr, "Error decrypting message: %s\n", err);
    goto free_stuff;
}
printf("Decrypted message: %s\n", decrypt);

getchar();

free_stuff:
RSA_free(keypair);
BIO_free_all(pub);
BIO_free_all(pri);
free(pri_key);
free(pub_key);
free(encrypt);
free(decrypt);
free(err);
}*/
