/* Example program to test opencryptoki
* build:
gcc sm2_test.c -g -O0 -o sm2_test -lopencryptoki -ldl -I/usr/lib/pkcs11/common \
    -I/usr/include/opencryptoki -L/usr/lib64/opencryptoki
*
* execute: ./sm_test -s <slot> -p <PIN> */
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pkcs11types.h>
#include <string.h>
#include <unistd.h>

CK_FUNCTION_LIST  *funcs;

#define OCKSHAREDLIB "libopencryptoki.so"

void *lib_ock;
char *pin = NULL;
int count, arg;
CK_SLOT_ID slotID = 0;
CK_ULONG ecKeyLen = 2048, cipherTextLen = 0, clearTextLen = 0;
CK_BYTE *pCipherText = NULL, *pClearText = NULL;
CK_BYTE *pECCipher = NULL, *pECClear = NULL;
CK_FLAGS rw_sessionFlags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
CK_SESSION_HANDLE hSession;

CK_BYTE msg[] = "The quick brown fox jumps over the lazy dog";
CK_ULONG msgLen = sizeof(msg);
CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

typedef struct signVerifyParam {
    CK_MECHANISM_TYPE   mechtype;
    CK_ULONG        inputlen;
    CK_ULONG        parts; /* 0 means process in 1 chunk via C_Sign, >0 means process in n chunks via C_SignUpdate/C_SignFinal */
} _signVerifyParam;

_signVerifyParam signVerifyInput[] = {
    { CKM_SM2, 20, 0}, /*
    { CKM_IBM_SM2_SM3, 32, 4},
    { CKM_IBM_SM2_SM3, 48, 0 },
    { CKM_IBM_SM2_SM3, 64, 0 } */
};

CK_BYTE sm2sm3_iv[] = { 0x31, 0x32, 0x33, 0x34,
                        0x35, 0x36, 0x37, 0x38 };


/*** <insert helper functions (provided below) here> ***/
/*** usage / help ***/
void usage(void) {
    printf("Usage:\n");
    printf(" -s <slot number> \n");
    printf(" -p <user PIN>\n");
    printf("\n");
    exit (8);
}

int do_GetFunctionList( void )
{
   CK_RV  rc;
   CK_RV  (*pfoo)();
   void    *d;
   char    *e;
   char    *f = OCKSHAREDLIB;

   e = getenv("PKCSLIB");
   if ( e == NULL) {
      e = f;
     // return FALSE;
   }
   d = dlopen(e, RTLD_NOW);
   if ( d == NULL ) {
      return FALSE;
   }

   pfoo = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
   if (pfoo == NULL ) {
      return FALSE;
   }
   rc = pfoo(&funcs);

   if (rc != CKR_OK) {
      printf("C_GetFunctionList rc=%s", p11_get_ckr(rc));
      return FALSE;
   }

   return TRUE;

}

/*
* initialize
*/
CK_RV init(void) {
    CK_RV rc;
    lib_ock = dlopen(OCKSHAREDLIB, RTLD_GLOBAL | RTLD_NOW);
    if (!lib_ock) {
        printf("Error loading shared lib ¡¯%s¡¯ [%s]", OCKSHAREDLIB, dlerror());
        return 1;
    }
    rc = funcs->C_Initialize(NULL);
    if (rc != CKR_OK) {
        printf("Error initializing the opencryptoki library: 0x%X\n", rc);
    }
    return CKR_OK;
}

/*
* finalize
*/
CK_RV finalize(void) {
    CK_RV rc;
    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        printf("Error during finalize: %x\n", rc);
        return rc;
    }
    if (pCipherText) free(pCipherText);
    if (pClearText) free(pClearText);
    if (pECCipher) free(pECCipher);
    if (pECClear) free(pECClear);
    return CKR_OK;
}

/*
* opensession
*/
CK_RV openSession(CK_SLOT_ID slotID, CK_FLAGS sFlags,
                  CK_SESSION_HANDLE_PTR phSession) {
    CK_RV rc;
    rc = funcs->C_OpenSession(slotID, sFlags, NULL, NULL, phSession);
    if (rc != CKR_OK) {
        printf("Error opening session: %x\n", rc);
        return rc;
    }
    printf("Open session successful.\n");
    return CKR_OK;
}

/*
* closesession
*/
CK_RV closeSession(CK_SESSION_HANDLE hSession) {
    CK_RV rc;
    rc = funcs->C_CloseSession(hSession);
    if (rc != CKR_OK) {
        printf("Error closing session: 0x%X\n", rc);
        return rc;
    }
    printf("Close session successful.\n");
    return CKR_OK;
}

/*
* login
*/
CK_RV loginSession(CK_USER_TYPE userType, CK_CHAR_PTR pPin,
                   CK_ULONG ulPinLen, CK_SESSION_HANDLE hSession) {
    CK_RV rc;
    rc = funcs->C_Login(hSession, userType, pPin, ulPinLen);
    if (rc != CKR_OK) {
        printf("Error login session: %x\n", rc);
        return rc;
    }
    printf("Login session successful.\n");
    return CKR_OK;
}

/*
* logout
*/
CK_RV logoutSession(CK_SESSION_HANDLE hSession) {
    CK_RV rc;
    rc = funcs->C_Logout(hSession);
    if (rc != CKR_OK) {
        printf("Error logout session: %x\n", rc);
        return rc;
    }
    printf("Logout session successful.\n");
    return CKR_OK;
}


/*
* SM key generate
*/
CK_RV generateSM2KeyPair(CK_SESSION_HANDLE hSession, CK_ULONG keySize,
                        CK_OBJECT_HANDLE_PTR publ_key, CK_OBJECT_HANDLE_PTR priv_key ) {

    CK_RV rc;

    static CK_OBJECT_CLASS publ_class = CKO_PUBLIC_KEY;
    static CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
    CK_MECHANISM mech;
    CK_ATTRIBUTE publ_tmpl[] = {
            {CKA_CLASS, &publ_class, sizeof(publ_class) },
    };

    CK_ATTRIBUTE priv_tmpl[] = {
            {CKA_CLASS, &priv_class, sizeof(priv_class) },
    };
    mech.mechanism = CKM_SM2_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rc = funcs->C_GenerateKeyPair(hSession, &mech,
                                  &publ_tmpl,
                                  sizeof(publ_tmpl)/sizeof (CK_ATTRIBUTE),
                                  &priv_tmpl,
                                  sizeof(priv_tmpl)/sizeof (CK_ATTRIBUTE),
                                  publ_key,
                                  priv_key);

    if (rc != CKR_OK) {
        printf("Error generating SM keys: 0x%08lx\n", rc);
        return rc;
    }
    printf("SM2 Key generation successful.\n");
}

/*
* SM sign/verify
*/
CK_RV SignVerifySM2(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechType,
                       CK_ULONG inputlen, CK_ULONG parts,
                       CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE publ_key) {
    CK_RV rc;
    CK_BYTE_PTR  data = NULL, signature = NULL;
    CK_ULONG  signaturelen, i;
    CK_MECHANISM smMechanism;

    smMechanism.mechanism = mechType;
    smMechanism.pParameter = 0;
    smMechanism.ulParameterLen = 0;

    data = calloc(sizeof(CK_BYTE), inputlen);
    if (data == NULL) {
        printf("Can't allocate memory for %lu bytes", sizeof(CK_BYTE) * inputlen);
        rc = -1;
        return rc;
    }
    for (i = 0; i < inputlen; i++) {
        data[i] = (i + 1) % 255;
    }

    rc = funcs->C_SignInit(hSession, &smMechanism, priv_key);
    if (rc != CKR_OK) {
        printf("Error C_SignInit: %x\n", rc);
        return rc;
    }

    if (parts > 0) {
        for (i = 0; i < parts; i++) {
            rc = funcs->C_SignUpdate(hSession, data, inputlen);
            if (rc != CKR_OK) {
                printf("Error C_SignUpdate: %x\n", rc);
                return rc;
            }
        }

        /* get signature length */
        rc = funcs->C_SignFinal(hSession, signature, &signaturelen);
        if (rc != CKR_OK) {
            printf("Error C_SignFinal: %x\n", rc);
            return rc;
        }
    }
    else {
        rc = funcs->C_Sign(hSession, data, inputlen, NULL, &signaturelen);
        if (rc != CKR_OK) {
            printf("Error C_Sign: %x\n", rc);
            return rc;
        }
    }
    signature = calloc(sizeof(CK_BYTE), signaturelen);
    if (signature == NULL) {
        printf("Can't allocate memory for %lu bytes", sizeof(CK_BYTE) * signaturelen);
        rc = -1;
        return rc;
    }

    if (parts > 0) {
        rc = funcs->C_SignFinal(hSession, signature, &signaturelen);
        if (rc != CKR_OK) {
            printf("Error C_SignFinal: %x\n", rc);
            return rc;
        }
    }
    else {
        rc = funcs->C_Sign(hSession, data, inputlen, signature, &signaturelen);
        if (rc != CKR_OK) {
            printf("Error C_Sign: %x\n", rc);
            return rc;
        }
    }
    printf("CKM_SM2 sign successful.\n");

    /****** Verify *******/
    rc = funcs->C_VerifyInit(hSession, &smMechanism, publ_key);
    if (rc != CKR_OK) {
        printf("Error C_VerifyInit: %x\n", rc);
        return rc;
    }

    if (parts > 0) {
        for (i = 0; i < parts; i++) {
            rc = funcs->C_VerifyUpdate(hSession, data, inputlen);
            if (rc != CKR_OK) {
                printf("Error C_VerifyUpdate: %x\n", rc);
                return rc;
            }
        }
        rc = funcs->C_VerifyFinal(hSession, signature, signaturelen);
        if (rc != CKR_OK) {
            printf("Error C_VerifyFinal: %x\n", rc);
            return rc;
        }
    }
    else {
        rc = funcs->C_Verify(hSession, data, inputlen, signature, signaturelen);
        if (rc != CKR_OK) {
            printf("Error C_Verify: %x\n", rc);
            return rc;
        }
    }

    // corrupt the signature and re-verify
    memcpy (signature, "ABCDEFGHIJKLMNOPQRSTUV", 26);

    rc = funcs->C_VerifyInit(hSession, &smMechanism, publ_key);
    if (rc != CKR_OK) {
        printf("Error C_VerifyInit: %x\n", rc);
        return rc;
    }

    if (parts > 0) {
        for (i = 0; i < parts; i++) {
            rc = funcs->C_VerifyUpdate(hSession, data, inputlen);
            if (rc != CKR_OK) {
                printf("Error C_VerifyUpdate: %x\n", rc);
                return rc;
            }
        }

        rc = funcs->C_VerifyFinal(hSession, signature, signaturelen);
        if (rc != CKR_SIGNATURE_INVALID) {
            printf("C_VerifyFinal rc=%s", rc);
            printf("     Expected CKR_SIGNATURE_INVALID\n");
            return rc;
        }
    }
    else {
        rc = funcs->C_Verify(hSession, data, inputlen, signature, signaturelen);
        if (rc != CKR_SIGNATURE_INVALID) {
            printf("C_Verify rc=%s", rc);
            printf("     Expected CKR_SIGNATURE_INVALID\n");
            return rc;
        }
    }

    printf("CKM_SM2 verify successful.\n");

    return CKR_OK;
}

int main(int argc, char *argv[]) {
    CK_RV  rc;
    int i;
    rc = do_GetFunctionList();
    if (rc == FALSE) {
        printf("do_getFunctionList(), rc=%s\n", p11_get_ckr(rc));
        return rc;
    }

    while ((arg = getopt (argc, argv, "s:p:")) != -1) {
        switch (arg) {
        case 's':
            slotID = atoi(optarg);
            break;
        case 'p':
            pin = malloc(strlen(optarg));
            strcpy(pin,optarg);
            break;
        default:
            printf("wrong option %c", arg);
            usage();
        }
    }
    if ((!pin) || (!slotID)) {
        printf("Incorrect parameter given!\n");
        usage();
        exit (8);
    }
    init();
    openSession(slotID, rw_sessionFlags, &hSession);
    loginSession(CKU_USER, pin, strlen(pin), hSession);
    generateSM2KeyPair(hSession, ecKeyLen, &hPublicKey, &hPrivateKey);
    for (i = 0; i < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); i++) {
        SignVerifySM2(
            hSession,
            signVerifyInput[i].mechtype,
            signVerifyInput[i].inputlen,
            signVerifyInput[i].parts,
            hPrivateKey,
            hPublicKey);
    }

    logoutSession(hSession);
    closeSession(hSession);
    finalize();
    return 0;
}
