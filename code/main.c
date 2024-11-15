#define REQUESTS_IMPLEMENTATION
#define USE_OPENSSL
//#define USE_BEARSSL
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