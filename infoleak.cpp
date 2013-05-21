/* 
 * Most vulnerable server P4P
 *
 * Compile with:
 *     g++ -m32 -pie -fPIE infoleak.cpp -o infoleak
 *
 * Exploit with DEP and ASLR ON
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define MAXRECVLEN 1024

//--------------------------------------------------//

class Input {
    char *ptr;
    int size;

    public:
      Input(char *, int);
      int getSize();
      virtual int getNewSize();
      char *read();
};

Input::Input(char *p, int n) {
    ptr = p;
    size = n;
}

int Input::getSize() {
    return size;
}

int Input::getNewSize() {
    return size;
}

char *Input::read() {
    char *s = (char *)malloc(size);

    memcpy(s, ptr, size);
    
    return s;
}

//--------------------------------------------------//

void handle_special(Input *i) {
    printf("Received a special input!\n");

    char *buf = i->read();
    buf = buf + 9;
    int size = i->getSize() - 9;

    delete i;

    char *special = (char *)malloc(size);
    memcpy(special, buf, size);
    printf("Special: %s.\n", special);
}

void handle_common(Input *i) {
    printf("Received a common input of size %d\n", i->getSize());
}

//--------------------------------------------------//

void process_input(char *inbuf, int len, int clientfd) {
    Input *inp = new Input(inbuf, len);

    char *buf = inp->read();
    int size = inp->getSize();

    if (!strncmp(buf, "jigcsaw1:", 9)) {
        handle_special(inp);
        buf = inp->read();
        size = inp->getSize();
    } else if (!strncmp(buf, "jigcsaw2:", 9)) {
        handle_special(inp);
        printf("This special input has size %d\n", inp->getNewSize());
    } else if(!strncmp(buf, "jigcsaw3", 8)) {
        void **c = (void **)malloc(sizeof(void *));
        *c = (void *)exit;
    } else {
        handle_common(inp);
    }

    send(clientfd, buf, size, 0);
}

int main(int argc, char *argv[]) {
    int sockfd, clientfd, clientlen, len;
    char inbuf[MAXRECVLEN + 1];
    struct sockaddr_in myaddr, clientaddr;

    if (argc < 2) {
        printf("Usage: %s port\n", argv[0]);
        exit(-1);
    }
    
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(atoi(argv[1]));

    bind(sockfd, (struct sockaddr *)&myaddr, sizeof(myaddr));
    listen(sockfd, 5);

    clientlen = sizeof(clientaddr);

    while (1) {
        clientfd = accept(sockfd, (struct sockaddr *)&clientaddr, (socklen_t *)&clientlen);
        
        len = recv(clientfd, inbuf, MAXRECVLEN, 0);
        inbuf[len] = '\0';
        
        process_input(inbuf, len + 1, clientfd);
        
        close(clientfd);
    }
    
    close(sockfd);

    return 0;
}

