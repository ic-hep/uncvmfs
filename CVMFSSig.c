/* Python CVMFS signature checker module.
 */

#include <Python.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

/* cvmfssig_verify_rsa - Verify a signature with an RSA key.
 * Args: key_file, hash, sig
 */
static PyObject *cvmfssig_verify_rsa(PyObject *self, PyObject *args)
{
  int retval;
  /* Input parameters. */
  int xHashLen, xSigLen;
  const char *xKeyFile, *xHash;
  const unsigned char *xSig;
  /* Key related gubbins. */
  FILE *xKeyFd = NULL;
  EVP_PKEY *xKeyIn = NULL;
  RSA *xKey = NULL;
  int xKeySize = -1;
  /* Buffer. */
  unsigned char *xOut = NULL;
  int xDecSize = -1;

  /* Process the function arguments. */
  retval = PyArg_ParseTuple(args, "ss#s#",
                            &xKeyFile,
                            &xHash, &xHashLen,
                            &xSig, &xSigLen);
  if (!retval)
    return NULL; /* Failed to parse arguments. */

  /* First we load the key file. */
  xKeyFd = fopen(xKeyFile, "r");
  if (!xKeyFd)
  {
    PyErr_Format(PyExc_IOError,
                 "Failed to open public key: %s", strerror(errno));
    return NULL;
  }
  if (!PEM_read_PUBKEY(xKeyFd, &xKeyIn, NULL, (void *)""))
  {
    fclose(xKeyFd);
    PyErr_SetString(PyExc_IOError, "Failed to process key file");
    return NULL;
  }
  fclose(xKeyFd);

  /* Convert the key from PKEY to RSA. */
  xKey = EVP_PKEY_get1_RSA(xKeyIn);
  EVP_PKEY_free(xKeyIn);
  if (!xKey)
  {
    PyErr_SetString(PyExc_IOError, "Failed to convert key to RSA");
    return NULL;
  }
  xKeySize = RSA_size(xKey);

  /* We can now allocate the memory we'll need for processing. */
  xOut = malloc(xKeySize);
  if (!xOut)
  {
    RSA_free(xKey);
    PyErr_NoMemory();
    return NULL;
  }

  /* Decrypt the signature using the RSA key. */
  xDecSize = RSA_public_decrypt(xSigLen, xSig, xOut, xKey, RSA_PKCS1_PADDING);
  RSA_free(xKey); /* We've finished with the key either way now. */
  if (xDecSize < 0)
  {
    /* Key file doesn't match the one used to make the signature. */
    free(xOut);
    PyErr_SetString(PyExc_IOError, "Signature decrypt error");
    return NULL;
  }

  /* Check the hash and (decrypted) signature match. */
  if ((xDecSize < 0) || (xDecSize != xHashLen))
  {
    /* Decrypted hash is wrong size. */
    free(xOut);
    PyErr_SetString(PyExc_ValueError, "Signature length invalid");
    return NULL;
  }
  if (memcmp(xOut, xHash, xHashLen))
  {
    /* Decrypted hash doesn't match. */
    free(xOut);
    PyErr_SetString(PyExc_ValueError, "Signature mismatch");
    return NULL;
  }

  /* Final tidy before exiting, return None for success. */
  free(xOut);
  Py_RETURN_NONE;
}

/* cvmfssig_verify_rsa - Verify a signature with an X509 cert.
 * Args: pem_string, hash, sig
 */
static PyObject *cvmfssig_verify_x509(PyObject *self, PyObject *args)
{
  int retval;
  /* Input parameters. */
  int xPemLen, xHashLen, xSigLen;
  const char *xPem, *xHash;
  const unsigned char *xSig;
  /* Certificate & context data. */
  BIO *xData = NULL;
  X509 *xCert = NULL;
  EVP_PKEY *xKey = NULL;
  EVP_MD_CTX xCTX;

  /* Process the function arguments. */
  retval = PyArg_ParseTuple(args, "s#s#s#",
                            &xPem, &xPemLen,
                            &xHash, &xHashLen,
                            &xSig, &xSigLen);
  if (!retval)
    return NULL; /* Failed to parse arguments. */

  /* Convert the X509 str into an X509 object & extract key. */
  xData = BIO_new_mem_buf((void *)xPem, xPemLen);
  if (!xData)
  {
    PyErr_NoMemory();
    return NULL;
  }
  if (!PEM_read_bio_X509(xData, &xCert, NULL, ""))
  {
    /* Failed to convert PEM -> X509. */
    BIO_free(xData);
    PyErr_SetString(PyExc_ValueError, "Failed to convert PEM to X509");
    return NULL;
  }
  BIO_free(xData);
  /* Key remains as a pointer into xCert (nothing extra to free)... */
  xKey = X509_get_pubkey(xCert);

  /* Intialise the verification context. */
  EVP_MD_CTX_init(&xCTX);
  retval = EVP_VerifyInit(&xCTX, EVP_sha1());
  if (!retval)
  {
    EVP_MD_CTX_cleanup(&xCTX);
    X509_free(xCert);
    PyErr_SetString(PyExc_ValueError, "Failed to initialise verifier");
    return NULL;
  }

  /* Actually verify the signature. */
  retval = EVP_VerifyUpdate(&xCTX, (void *)xHash, xHashLen);
  if (!retval)
  {
    EVP_MD_CTX_cleanup(&xCTX);
    X509_free(xCert);
    PyErr_SetString(PyExc_ValueError, "Failed to update verifier");
    return NULL;
  }

  retval = EVP_VerifyFinal(&xCTX, xSig, xSigLen, xKey);
  if (!retval)
  {
    EVP_MD_CTX_cleanup(&xCTX);
    X509_free(xCert);
    PyErr_SetString(PyExc_ValueError, "Invalid signature");
    return NULL;
  }

  /* If we got here, the signature is valid. */
  EVP_MD_CTX_cleanup(&xCTX);
  X509_free(xCert);

  /* Return None on sucess. */
  Py_RETURN_NONE;
}

/* cvmfssig_fingerprint - Returns the fingerprint of an X509 cert.
 */
static PyObject *cvmfssig_fingerprint(PyObject *self, PyObject *args)
{
  #define SHA1_HASH_LEN 20
  int i, retval;
  /* Parameters */
  int xPemLen;
  const char *xPem;
  /* Cert/openssl data. */
  BIO *xData = NULL;
  X509 *xCert = NULL;
  unsigned int xHashLen = SHA1_HASH_LEN;
  unsigned char xHash[SHA1_HASH_LEN] = {};
  /* Output string object (AB:CD:...\0). */
  char *xOutPtr;
  char xOutput[60] = {};

  /* Get the parameter. */
  retval = PyArg_ParseTuple(args, "s#", &xPem, &xPemLen);
  if (!retval)
    return NULL; /* Bad parameters. */

  /* Convert the PEM input into an X509 object via a BIO. */
  xData = BIO_new_mem_buf((void *)xPem, xPemLen);
  if (!xData)
  {
    PyErr_NoMemory();
    return NULL;
  }
  if (!PEM_read_bio_X509(xData, &xCert, NULL, ""))
  {
    /* Failed to convert PEM -> X509. */
    BIO_free(xData);
    PyErr_SetString(PyExc_ValueError, "Failed to convert PEM to X509");
    return NULL;
  }
  BIO_free(xData);

  /* Now calculate the fingerprint of the cert. */
  X509_digest(xCert, EVP_sha1(), xHash, &xHashLen);
  X509_free(xCert);

  /* Convert the hash into the expected format. */
  xOutPtr = xOutput;
  for (i = 0; i < SHA1_HASH_LEN; i++)
  {
    char xBuffer[3];
    /* Add a : if we are in the middle of the string. */
    if (i > 0)
    {
      *xOutPtr = ':';
      xOutPtr++;
    }
    /* Add the next two bytes. */
    sprintf(xBuffer, "%02X", xHash[i]);
    xOutPtr[0] = xBuffer[0];
    xOutPtr[1] = xBuffer[1];
    xOutPtr += 2;
  }

  return Py_BuildValue("s", xOutput);
}

static PyMethodDef CVMFSSIG_METHODS[] =
{
  { "verify_rsa", cvmfssig_verify_rsa, METH_VARARGS,
      "Check a CVMFS signature block using an RSA key." },
  { "verify_x509", cvmfssig_verify_x509, METH_VARARGS,
      "Check a CVMFS signature block using an X509 cert." },
  { "fingerprint", cvmfssig_fingerprint, METH_VARARGS,
      "Returns the SHA1 fingerprint of an X509 cert." },
  { NULL, NULL, 0, NULL },
};

PyMODINIT_FUNC initCVMFSSig(void)
{
  Py_InitModule("CVMFSSig", CVMFSSIG_METHODS);
  OpenSSL_add_all_algorithms();
}

