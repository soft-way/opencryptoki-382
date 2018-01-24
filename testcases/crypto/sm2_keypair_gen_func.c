/* ------------------------------------------------------------ *
 * file:        sm2_keypair_gen_func.c                                   *
 * purpose:     Example code for creating elliptic curve        *
 *              cryptography (ECC) key pairs                    *
 * author:      01/26/2015 Frank4DD                             *
 * http://fm4dd.com/openssl/eckeycreate.htm                     *
 * gcc -o sm2_keypair_gen_fun sm2_keypair_gen_func.c -I/opt/gmssl/include -L/opt/gmssl/lib -lssl -lcrypto              *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#define ECCTYPE "sm2p256v1"

#define TRACE_HEX(x, y, z) traceit_hex(__FILE__, __LINE__, __func__, x, y, z)

unsigned char bin_char2hex(int i) {
    if (i >= 0 && i <= 9) {
        return i + '0';
    }

    if (i >= 10 && i <= 15) {
        return i + 'A' - 10;
    }
    return 'X';
}

int bin2hex_format(unsigned char *in, int in_len, unsigned char *out, int *out_len) {
    if (in == NULL  || out == NULL || out_len == NULL) {
        return 0;
    }

    int i=0;
    unsigned char *p = out;
    while (i < in_len) {
        if (i != 0) {
            if (i % 4 == 0) { // add one space for each 4 bytes
                *p++ = ' ';
            }
            if (i % 16 == 0) { // add more one space for each 8 bytes
                *p++ = ' ';
            }
            if (i % 32 == 0 && i != 0) { // add line feed for each 32 bytes
                *p++ = '\n';
            }
        }
        *p++ = bin_char2hex(in[i] >> 4);
        *p++ = bin_char2hex(in[i] & 0x0F);
        i++;
    }
    *p = '\0';
    *out_len = p-out;

    return *out_len;
}

int traceit_hex(char *file, unsigned long line, const char *func, char *title, char *out, int out_len) {
    unsigned char buf[8192];
    int len = 0;
    if (out != NULL) {
        bin2hex_format(out, out_len, buf, &len);
    }
    buf[len] = '\0';

    printf("[%s:%d %s] INFO: %s(%d):\n%s\n", file, line, func, title, out_len, buf);

    return len;
}

int main() {

  BIO               *outbio = NULL;
  EC_KEY            *myecc  = NULL;
  EVP_PKEY          *pkey   = NULL;
  int               eccgrp;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Create a EC key sructure, setting the group type from NID  *
   * ---------------------------------------------------------- */
  eccgrp = OBJ_txt2nid(ECCTYPE);
  myecc = EC_KEY_new_by_curve_name(eccgrp);

  /* -------------------------------------------------------- *
   * For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag*
   * ---------------------------------------------------------*/
  EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

  /* -------------------------------------------------------- *
   * Create the public/private EC key pair here               *
   * ---------------------------------------------------------*/
  if (! (EC_KEY_generate_key(myecc)))
    BIO_printf(outbio, "Error generating the ECC key.");

  /* -------------------------------------------------------- *
   * Converting the EC key into a PKEY structure let us       *
   * handle the key just like any other key pair.             *
   * ---------------------------------------------------------*/
  pkey = EVP_PKEY_new();
  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
    BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

  /* -------------------------------------------------------- *
   * Now we show how to extract EC-specifics from the key     *
   * ---------------------------------------------------------*/
  myecc = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

  /* ---------------------------------------------------------- *
   * Here we print the key length, and extract the curve type.  *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
  BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

  /* ---------------------------------------------------------- *
   * Here we print the private/public key data in PEM format.   *
   * ---------------------------------------------------------- */
  if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    BIO_printf(outbio, "Error writing private key data in PEM format");

  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");
/*
  unsigned char publblob[1024];
  int publblobsize = i2d_PublicKey(pkey, &publblob);
  if (publblobsize == -1) {
      printf("Error fetching public key.\n");
      return 1;
  } else {
      TRACE_HEX("Public key value", publblob, publblobsize);
  }

  unsigned char privblob[1024];
  int privblobsize = i2d_PrivateKey(pkey, &privblob);
  if (privblobsize == -1) {
      printf("Error fetching private key.\n");
      return 1;
  } else {
      TRACE_HEX("Private key value", privblob, privblobsize);
  }
*/


  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  EVP_PKEY_free(pkey);
  EC_KEY_free(myecc);
  BIO_free_all(outbio);

  exit(0);
}
