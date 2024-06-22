#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wincrypt.h>
#include <openssl/rand.h>

HINSTANCE g_hModule = NULL;

BOOL WINAPI
DllMain(HINSTANCE hinstDLL,
        DWORD fdwReason,
        LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        g_hModule = hinstDLL;
    }

    return TRUE;
}

/*
//
// Callback prototypes
//

typedef BOOL (WINAPI *CRYPT_VERIFY_IMAGE_A)(LPCSTR  szImage, CONST BYTE *pbSigData);
typedef BOOL (WINAPI *CRYPT_VERIFY_IMAGE_W)(LPCWSTR szImage, CONST BYTE *pbSigData);
typedef void (*CRYPT_RETURN_HWND)(HWND *phWnd);


//
// Structures for CSPs
//

typedef struct _VTableProvStruc {
    DWORD                Version;
    CRYPT_VERIFY_IMAGE_A FuncVerifyImage;
    CRYPT_RETURN_HWND    FuncReturnhWnd;
    DWORD                dwProvType;
    BYTE                *pbContextInfo;
    DWORD                cbContextInfo;
    LPSTR                pszProvName;
} VTableProvStruc,      *PVTableProvStruc;

typedef struct _VTableProvStrucW {
    DWORD                Version;
    CRYPT_VERIFY_IMAGE_W FuncVerifyImage;
    CRYPT_RETURN_HWND    FuncReturnhWnd;
    DWORD                dwProvType;
    BYTE                *pbContextInfo;
    DWORD                cbContextInfo;
    LPWSTR               pszProvName;
} VTableProvStrucW,     *PVTableProvStrucW;
*/

/*
 -  CPAcquireContext
 -
 *  Purpose:
 *               The CPAcquireContext function is used to acquire a context
 *               handle to a cryptographic service provider (CSP).
 *
 *
 *  Parameters:
 *               OUT phProv         -  Handle to a CSP
 *               IN  szContainer    -  Pointer to a string which is the
 *                                     identity of the logged on user
 *               IN  dwFlags        -  Flags values
 *               IN  pVTable        -  Pointer to table of function pointers
 *
 *  Returns:
 */

BOOL WINAPI
CPAcquireContext(OUT HCRYPTPROV *phProv,
                 IN  LPCSTR szContainer,
                 IN  DWORD dwFlags,
                 IN  PVTableProvStruc pVTable)
{
    *phProv = (HCRYPTPROV)NULL; // Replace NULL with your own structure.
    return TRUE;
}


/*
 -      CPReleaseContext
 -
 *      Purpose:
 *               The CPReleaseContext function is used to release a
 *               context created by CryptAcquireContext.
 *
 *     Parameters:
 *               IN  phProv        -  Handle to a CSP
 *               IN  dwFlags       -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPReleaseContext(IN  HCRYPTPROV hProv,
                 IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPGenKey
 -
 *  Purpose:
 *                Generate cryptographic keys
 *
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      Algid   -  Algorithm identifier
 *               IN      dwFlags -  Flags values
 *               OUT     phKey   -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPGenKey(IN  HCRYPTPROV hProv,
         IN  ALG_ID Algid,
         IN  DWORD dwFlags,
         OUT HCRYPTKEY *phKey)
{
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    return TRUE;
}


/*
 -  CPDeriveKey
 -
 *  Purpose:
 *                Derive cryptographic keys from base data
 *
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      Algid      -  Algorithm identifier
 *               IN      hBaseData -   Handle to base data
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPDeriveKey(IN  HCRYPTPROV hProv,
            IN  ALG_ID Algid,
            IN  HCRYPTHASH hHash,
            IN  DWORD dwFlags,
            OUT HCRYPTKEY *phKey)
{
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    return TRUE;
}


/*
 -  CPDestroyKey
 -
 *  Purpose:
 *                Destroys the cryptographic key that is being referenced
 *                with the hKey parameter
 *
 *
 *  Parameters:
 *               IN      hProv  -  Handle to a CSP
 *               IN      hKey   -  Handle to a key
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyKey(IN  HCRYPTPROV hProv,
             IN  HCRYPTKEY hKey)
{
    return TRUE;
}


/*
 -  CPSetKeyParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hKey    -  Handle to a key
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetKeyParam(IN  HCRYPTPROV hProv,
              IN  HCRYPTKEY hKey,
              IN  DWORD dwParam,
              IN  CONST BYTE *pbData,
              IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPGetKeyParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetKeyParam(IN  HCRYPTPROV hProv,
              IN  HCRYPTKEY hKey,
              IN  DWORD dwParam,
              OUT LPBYTE pbData,
              IN OUT LPDWORD pcbDataLen,
              IN  DWORD dwFlags)
{
    *pcbDataLen = 0;
    return TRUE;
}


/*
 -  CPSetProvParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetProvParam(IN  HCRYPTPROV hProv,
               IN  DWORD dwParam,
               IN  CONST BYTE *pbData,
               IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPGetProvParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN OUT  pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetProvParam(IN  HCRYPTPROV hProv,
               IN  DWORD dwParam,
               OUT LPBYTE pbData,
               IN OUT LPDWORD pcbDataLen,
               IN  DWORD dwFlags)
{
    *pcbDataLen = 0;
    return TRUE;
}


/*
 -  CPSetHashParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hHash   -  Handle to a hash
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetHashParam(IN  HCRYPTPROV hProv,
               IN  HCRYPTHASH hHash,
               IN  DWORD dwParam,
               IN  CONST BYTE *pbData,
               IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPGetHashParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetHashParam(IN  HCRYPTPROV hProv,
               IN  HCRYPTHASH hHash,
               IN  DWORD dwParam,
               OUT LPBYTE pbData,
               IN OUT LPDWORD pcbDataLen,
               IN  DWORD dwFlags)
{
    *pcbDataLen = 0;
    return TRUE;
}


/*
 -  CPExportKey
 -
 *  Purpose:
 *                Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *  Parameters:
 *               IN  hProv         - Handle to the CSP user
 *               IN  hKey          - Handle to the key to export
 *               IN  hPubKey       - Handle to exchange public key value of
 *                                   the destination user
 *               IN  dwBlobType    - Type of key blob to be exported
 *               IN  dwFlags       - Flags values
 *               OUT pbData        -     Key blob data
 *               IN OUT pdwDataLen - Length of key blob in bytes
 *
 *  Returns:
 */

BOOL WINAPI
CPExportKey(IN  HCRYPTPROV hProv,
            IN  HCRYPTKEY hKey,
            IN  HCRYPTKEY hPubKey,
            IN  DWORD dwBlobType,
            IN  DWORD dwFlags,
            OUT LPBYTE pbData,
            IN OUT LPDWORD pcbDataLen)
{
    *pcbDataLen = 0;
    return TRUE;
}


/*
 -  CPImportKey
 -
 *  Purpose:
 *                Import cryptographic keys
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the CSP user
 *               IN  pbData    -  Key blob data
 *               IN  dwDataLen -  Length of the key blob data
 *               IN  hPubKey   -  Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwFlags   -  Flags values
 *               OUT phKey     -  Pointer to the handle to the key which was
 *                                Imported
 *
 *  Returns:
 */

BOOL WINAPI
CPImportKey(IN  HCRYPTPROV hProv,
            IN  CONST BYTE *pbData,
            IN  DWORD cbDataLen,
            IN  HCRYPTKEY hPubKey,
            IN  DWORD dwFlags,
            OUT HCRYPTKEY *phKey)
{
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    return TRUE;
}


/*
 -  CPEncrypt
 -
 *  Purpose:
 *                Encrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of plaintext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be encrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    encrypted
 *               IN dwBufLen       -  Size of Data buffer
 *
 *  Returns:
 */

BOOL WINAPI
CPEncrypt(IN  HCRYPTPROV hProv,
          IN  HCRYPTKEY hKey,
          IN  HCRYPTHASH hHash,
          IN  BOOL fFinal,
          IN  DWORD dwFlags,
          IN OUT LPBYTE pbData,
          IN OUT LPDWORD pcbDataLen,
          IN  DWORD cbBufLen)
{
    *pcbDataLen = 0;
    return TRUE;
}


/*
 -  CPDecrypt
 -
 *  Purpose:
 *                Decrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of ciphertext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be decrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    decrypted
 *
 *  Returns:
 */

BOOL WINAPI
CPDecrypt(IN  HCRYPTPROV hProv,
          IN  HCRYPTKEY hKey,
          IN  HCRYPTHASH hHash,
          IN  BOOL fFinal,
          IN  DWORD dwFlags,
          IN OUT LPBYTE pbData,
          IN OUT LPDWORD pcbDataLen)
{
    *pcbDataLen = 0;
    return TRUE;
}


/*
 -  CPCreateHash
 -
 *  Purpose:
 *                initate the hashing of a stream of data
 *
 *
 *  Parameters:
 *               IN  hUID    -  Handle to the user identifcation
 *               IN  Algid   -  Algorithm identifier of the hash algorithm
 *                              to be used
 *               IN  hKey   -   Optional handle to a key
 *               IN  dwFlags -  Flags values
 *               OUT pHash   -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPCreateHash(IN  HCRYPTPROV hProv,
             IN  ALG_ID Algid,
             IN  HCRYPTKEY hKey,
             IN  DWORD dwFlags,
             OUT HCRYPTHASH *phHash)
{
    *phHash = (HCRYPTHASH)NULL;  // Replace NULL with your own structure.
    return TRUE;
}


/*
 -  CPHashData
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a stream of data
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  pbData    -  Pointer to data to be hashed
 *               IN  dwDataLen -  Length of the data to be hashed
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPHashData(IN  HCRYPTPROV hProv,
           IN  HCRYPTHASH hHash,
           IN  CONST BYTE *pbData,
           IN  DWORD cbDataLen,
           IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPHashSessionKey
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a key object.
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  hKey      -  Handle to a key object
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 *               CRYPT_FAILED
 *               CRYPT_SUCCEED
 */

BOOL WINAPI
CPHashSessionKey(IN  HCRYPTPROV hProv,
                 IN  HCRYPTHASH hHash,
                 IN  HCRYPTKEY hKey,
                 IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPSignHash
 -
 *  Purpose:
 *                Create a digital signature from a hash
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  dwKeySpec    -  Key pair to that is used to sign with
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *               OUT pbSignature  -  Pointer to signature data
 *               IN OUT dwHashLen -  Pointer to the len of the signature data
 *
 *  Returns:
 */

BOOL WINAPI
CPSignHash(IN  HCRYPTPROV hProv,
           IN  HCRYPTHASH hHash,
           IN  DWORD dwKeySpec,
           IN  LPCWSTR szDescription,
           IN  DWORD dwFlags,
           OUT LPBYTE pbSignature,
           IN OUT LPDWORD pcbSigLen)
{
    *pcbSigLen = 0;
    return TRUE;
}


/*
 -  CPDestroyHash
 -
 *  Purpose:
 *                Destroy the hash object
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash)
{
    return TRUE;
}


/*
 -  CPVerifySignature
 -
 *  Purpose:
 *                Used to verify a signature against a hash object
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  pbSignture   -  Pointer to signature data
 *               IN  dwSigLen     -  Length of the signature data
 *               IN  hPubKey      -  Handle to the public key for verifying
 *                                   the signature
 *               IN  sDescription -  String describing the signed data
 *               IN  dwFlags      -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPVerifySignature(IN  HCRYPTPROV hProv,
                  IN  HCRYPTHASH hHash,
                  IN  CONST BYTE *pbSignature,
                  IN  DWORD cbSigLen,
                  IN  HCRYPTKEY hPubKey,
                  IN  LPCWSTR szDescription,
                  IN  DWORD dwFlags)
{
    return TRUE;
}


/*
 -  CPGenRandom
 -
 *  Purpose:
 *                Used to fill a buffer with random bytes
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the user identifcation
 *               IN  dwLen         -  Number of bytes of random data requested
 *               IN OUT pbBuffer   -  Pointer to the buffer where the random
 *                                    bytes are to be placed
 *
 *  Returns:
 */

BOOL WINAPI
CPGenRandom(IN  HCRYPTPROV hProv,
            IN  DWORD cbLen,
            OUT LPBYTE pbBuffer)
{
    int ret = RAND_bytes(pbBuffer, cbLen);
    return ret == 1;
}


/*
 -  CPGetUserKey
 -
 *  Purpose:
 *                Gets a handle to a permanent user key
 *
 *
 *  Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               IN  dwKeySpec  -  Specification of the key to retrieve
 *               OUT phUserKey  -  Pointer to key handle of retrieved key
 *
 *  Returns:
 */

BOOL WINAPI
CPGetUserKey(IN  HCRYPTPROV hProv,
             IN  DWORD dwKeySpec,
             OUT HCRYPTKEY *phUserKey)
{
    *phUserKey = 0;
    return TRUE;
}


/*
 -  CPDuplicateHash
 -
 *  Purpose:
 *                Duplicates the state of a hash and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hHash          -  Handle to a hash
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phHash         -  Handle to the new hash
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateHash(IN  HCRYPTPROV hProv,
                IN  HCRYPTHASH hHash,
                IN  LPDWORD pdwReserved,
                IN  DWORD dwFlags,
                OUT HCRYPTHASH *phHash)
{
    *phHash = (HCRYPTHASH)NULL;  // Replace NULL with your own structure.
    return TRUE;
}


/*
 -  CPDuplicateKey
 -
 *  Purpose:
 *                Duplicates the state of a key and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hKey           -  Handle to a key
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phKey          -  Handle to the new key
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateKey(IN  HCRYPTPROV hProv,
               IN  HCRYPTKEY hKey,
               IN  LPDWORD pdwReserved,
               IN  DWORD dwFlags,
               OUT HCRYPTKEY *phKey)
{
    *phKey = (HCRYPTKEY)NULL;    // Replace NULL with your own structure.
    return TRUE;
}
