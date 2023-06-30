# wincerts
A Python interface to cryptographic data in the Windows Certificate Store.

## Quick start
Not yet packaged.  

## Usage
Here is how you can create an SSL/TLS context using a certificate (with private key) contained in the Windows Certificate Store.

```python
import wincerts

my_store = wincerts.CertStore('My')
for pkcs12 in my_store.iter_pkcs12():
    if not pkcs12.cert_expired and pkcs12.has_private_key and 'digitalSignature' in pkcs12.cert_keyusages:
        print('Valid certificate found')
        break

ssl_ctx = pkcs12.create_ssl_context()
```

## Reference Documentation
The references to the source docs for getting this together. 

* [CERT_CONTEXT structure](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context)
* [CertGetNameStringW function (wincrypt.h)](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw)
* [Cryptograhic API](https://referencesource.microsoft.com/#System/security/system/security/cryptography/cryptoapi.cs)
