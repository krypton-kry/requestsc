# requestsc

A lightweight, header only HTTP/HTTPS client library written in C. requestsc aims to be easy to use, with minimal dependencies (only for cryptography).

Currently supported OS : Windows & Linux
Currently supported Cryptography Library : OpenSSL

## Usage

Include the header file and link the library in your project:
```
#define REQUESTS_IMPLEMENTATION // define this
#define USE_OPENSSL  // backend to use
#include "requests.h"
```
- In Windows link against Ws2_32.lib libssl.lib libcrypto.lib
- In linux link against lssl lcrypto
## Example

Here's a basic example of how to use requestsc to make a GET request:

```c
#define REQUESTS_IMPLEMENTATION
#define USE_OPENSSL
#include "requests.h"

int main(){
    requests_init();
    response res = request("https://github.com/", GET);
    
    if(res.status_code == 200){
        printf("%s\n", res.data);
    } else {
        printf("status: %d\n", res.status_code);
    }
    
    free(res.data);
    requests_cleanup();
    
}
```

## OpenSSL
- It's linked to libssl and libcrypto, in Windows you can download the binaries from [here](https://wiki.openssl.org/index.php/Binaries)

- In Linux you can simply install openssl using your package manager.

Example in Arch :

```
sudo pacman -Syu openssl
```
## ToDo
- [ ] Documentation
- [ ] BearSSL Backend
- [ ] Parse URL properly
- [ ] username / password from url
- [ ] port from url
- [ ] sanitize the url
- [ ] parse queries
- [ ] Header Support
- [ ] Support for requests other than GET
- [ ] Parse Headers Properly
- [ ] Support for other OS

Contributions are welcome! :)
