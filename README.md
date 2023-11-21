# Internet_Privacy
- 이름 : 김건희
- 이메일 : gunhee2001@naver.com
- 연락처 : 010-7187-0977
- 과제 개발 환경 : macOS 14.1.1 vscode
- 사용한 라이브러리 : 
```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/x509.h>
  #include <openssl/x509v3.h>
  #include <openssl/pem.h>
  #include <openssl/ocsp.h>
  #include <openssl/bio.h>
  #include <curl/curl.h>
```
- 과제 컴파일 명령어 : gcc sampleClient.c -o sampleClient -I/opt/homebrew/Cellar/openssl@1.1/1.1.1u/include -L/opt/homebrew/Cellar/openssl@1.1/1.1.1u/lib -lssl -lcrypto -lcurl
