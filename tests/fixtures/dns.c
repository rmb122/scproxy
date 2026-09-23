#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static const unsigned char query[] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'d','n','s',4,'t','e','s','t',0,0,1,0,1};
static struct sockaddr_in resolver;
static void check_peer(struct sockaddr_in *peer) {
    assert(peer->sin_family == AF_INET && peer->sin_port == htons(53));
    assert(peer->sin_addr.s_addr == resolver.sin_addr.s_addr);
}
static void check_answer(unsigned char *data, ssize_t length) {
    assert(length > (ssize_t)sizeof(query));
    assert(data[0] == 0x12 && data[1] == 0x34 && data[7] == 1);
    assert(data[length-4] == 198 && (data[length-3] == 18 || data[length-3] == 19));
}
static void *reader(void *value) {
    int fd = *(int *)value;
    unsigned char data[512];
    check_answer(data, recv(fd, data, sizeof(data), 0));
    return NULL;
}
int main(void) {
    alarm(10);
    resolver.sin_family = AF_INET;
    resolver.sin_port = htons(53);
    assert(inet_pton(AF_INET, "198.18.0.1", &resolver.sin_addr) == 1);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    int duplicate = dup(fd), ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN, .data.fd = duplicate};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, duplicate, &event) == 0);
    assert(sendto(fd, query, sizeof(query), 0, (void *)&resolver, sizeof(resolver)) == sizeof(query));
    assert(epoll_wait(ep, &event, 1, 2000) == 1);
    unsigned char data[512];
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    ssize_t count = recvfrom(duplicate, data, 5, MSG_PEEK | MSG_TRUNC, (void *)&peer, &length);
    assert(count > 5 && length == sizeof(peer));
    check_peer(&peer);
    length = 3;
    assert(recvfrom(fd, data, sizeof(data), 0, (void *)&peer, &length) == count);
    assert(length == sizeof(peer));
    check_answer(data, count);
    assert(connect(fd, (void *)&resolver, sizeof(resolver)) == 0);
    length = sizeof(peer);
    assert(getpeername(duplicate, (void *)&peer, &length) == 0);
    check_peer(&peer);
    struct iovec pieces[2] = {{(void *)query, 8}, {(void *)query + 8, sizeof(query) - 8}};
    assert(writev(fd, pieces, 2) == sizeof(query));
    count = read(duplicate, data, sizeof(data));
    check_answer(data, count);
    struct iovec sendvec = {(void *)query, sizeof(query)};
    struct mmsghdr sends[2] = {0}, receives[2] = {0};
    unsigned char replies[2][512];
    struct sockaddr_in peers[2];
    struct iovec receivevec[2] = {{replies[0],512},{replies[1],512}};
    for (int i=0;i<2;i++) {
        sends[i].msg_hdr.msg_iov = &sendvec;
        sends[i].msg_hdr.msg_iovlen = 1;
        receives[i].msg_hdr.msg_iov = &receivevec[i];
        receives[i].msg_hdr.msg_iovlen = 1;
        receives[i].msg_hdr.msg_name = &peers[i];
        receives[i].msg_hdr.msg_namelen = sizeof(peers[i]);
    }
    assert(sendmmsg(fd, sends, 2, 0) == 2);
    struct timespec timeout = {.tv_sec=2};
    assert(recvmmsg(fd, receives, 2, 0, &timeout) == 2);
    for (int i=0;i<2;i++) { check_answer(replies[i], receives[i].msg_len); check_peer(&peers[i]); }
    assert(timeout.tv_sec < 2);
    assert(sendmsg(fd, &sends[0].msg_hdr, 0) == sizeof(query));
    unsigned char first[5], rest[507];
    struct iovec scatter[2] = {{first,5},{rest,507}};
    struct msghdr receive = {.msg_iov=scatter, .msg_iovlen=2, .msg_name=&peer, .msg_namelen=sizeof(peer)};
    count = recvmsg(fd, &receive, 0);
    assert(count > 5 && first[0] == 0x12 && first[1] == 0x34);
    check_peer(&peer);
    assert(recv(fd, data, sizeof(data), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    struct timeval tv = {.tv_usec=30000};
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    assert(recv(fd, data, sizeof(data), 0) == -1 && errno == EAGAIN);
    tv.tv_usec = 0;
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
    timeout = (struct timespec){.tv_nsec=30000000};
    assert(recvmmsg(fd, receives, 1, 0, &timeout) == 0);
    pthread_t thread;
    assert(pthread_create(&thread, NULL, reader, &duplicate) == 0);
    usleep(30000);
    assert(send(fd, query, sizeof(query), 0) == sizeof(query));
    assert(pthread_join(thread, NULL) == 0);
    assert(sendto(fd, (void *)1, 10, 0, (void *)&resolver, sizeof(resolver)) == -1 && errno == EFAULT);
    assert(fcntl(fd, F_GETFL) & O_NONBLOCK ? 0 : 1);
    close(ep); close(duplicate); close(fd);
    puts("DNS ABI OK");
    return 0;
}
