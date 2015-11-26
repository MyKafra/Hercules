// Copyright (c) Hercules Dev Team, licensed under GNU GPL.
// See the LICENSE file
// Portions Copyright (c) Athena Dev Teams

#define HERCULES_CORE

#include "config/core.h" // SHOW_SERVER_STATS
#include "socket.h"

#include "common/HPM.h"
#include "common/cbasetypes.h"
#include "common/db.h"
#include "common/memmgr.h"
#include "common/mmo.h"
#include "common/nullpo.h"
#include "common/showmsg.h"
#include "common/strlib.h"
#include "common/timer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef WIN32
#	include "common/winapi.h"
#else
#	include <arpa/inet.h>
#	include <errno.h>
#	include <net/if.h>
#	include <netdb.h>
#if defined __linux__ || defined __linux
#       include <linux/tcp.h>
#else
#	include <netinet/in.h>
#	include <netinet/tcp.h>
#endif
#	include <sys/ioctl.h>
#	include <sys/socket.h>
#	include <sys/time.h>
#	include <unistd.h>

#	ifndef SIOCGIFCONF
#		include <sys/sockio.h> // SIOCGIFCONF on Solaris, maybe others? [Shinomori]
#	endif
#	ifndef FIONBIO
#		include <sys/filio.h> // FIONBIO on Solaris [FlavioJS]
#	endif

#	ifdef HAVE_SETRLIMIT
#		include <sys/resource.h>
#	endif
#endif

/**
 * Socket Interface Source
 **/
struct socket_interface sockt_s;
struct socket_interface *sockt;

struct socket_data **session;

#ifdef SEND_SHORTLIST
	// Add a fd to the shortlist so that it'll be recognized as a fd that needs
	// sending done on it.
	void send_shortlist_add_fd(int fd);
	// Do pending network sends (and eof handling) from the shortlist.
	void send_shortlist_do_sends();
#endif

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// global array of sockets (emulating linux)
// fd is the position in the array
static SOCKET sock_arr[FD_SETSIZE];
static int sock_arr_len = 0;

/// Returns the socket associated with the target fd.
///
/// @param fd Target fd.
/// @return Socket
#define fd2sock(fd) sock_arr[fd]

/// Returns the first fd associated with the socket.
/// Returns -1 if the socket is not found.
///
/// @param s Socket
/// @return Fd or -1
int sock2fd(SOCKET s)
{
	int fd;

	// search for the socket
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == s )
			break;// found the socket
	if( fd == sock_arr_len )
		return -1;// not found
	return fd;
}

/// Inserts the socket into the global array of sockets.
/// Returns a new fd associated with the socket.
/// If there are too many sockets it closes the socket, sets an error and
//  returns -1 instead.
/// Since fd 0 is reserved, it returns values in the range [1,FD_SETSIZE[.
///
/// @param s Socket
/// @return New fd or -1
int sock2newfd(SOCKET s)
{
	int fd;

	// find an empty position
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == INVALID_SOCKET )
			break;// empty position
	if( fd == ARRAYLENGTH(sock_arr) )
	{// too many sockets
		closesocket(s);
		WSASetLastError(WSAEMFILE);
		return -1;
	}
	sock_arr[fd] = s;
	if( sock_arr_len <= fd )
		sock_arr_len = fd+1;
	return fd;
}

int sAccept(int fd, struct sockaddr* addr, int* addrlen)
{
	SOCKET s;

	// accept connection
	s = accept(fd2sock(fd), addr, addrlen);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

int sClose(int fd)
{
	int ret = closesocket(fd2sock(fd));
	fd2sock(fd) = INVALID_SOCKET;
	return ret;
}

int sSocket(int af, int type, int protocol)
{
	SOCKET s;

	// create socket
	s = socket(af,type,protocol);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

char* sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

#define sBind(fd,name,namelen)                      bind(fd2sock(fd),(name),(namelen))
#define sConnect(fd,name,namelen)                   connect(fd2sock(fd),(name),(namelen))
#define sIoctl(fd,cmd,argp)                         ioctlsocket(fd2sock(fd),(cmd),(argp))
#define sListen(fd,backlog)                         listen(fd2sock(fd),(backlog))
#define sRecv(fd,buf,len,flags)                     recv(fd2sock(fd),(buf),(len),(flags))
#define sSelect                                     select
#define sSend(fd,buf,len,flags)                     send(fd2sock(fd),(buf),(len),(flags))
#define sSetsockopt(fd,level,optname,optval,optlen) setsockopt(fd2sock(fd),(level),(optname),(optval),(optlen))
#define sShutdown(fd,how)                           shutdown(fd2sock(fd),(how))
#define sFD_SET(fd,set)                             FD_SET(fd2sock(fd),(set))
#define sFD_CLR(fd,set)                             FD_CLR(fd2sock(fd),(set))
#define sFD_ISSET(fd,set)                           FD_ISSET(fd2sock(fd),(set))
#define sFD_ZERO                                    FD_ZERO

/////////////////////////////////////////////////////////////////////
#else
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif
/////////////////////////////////////////////////////////////////////

#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
#endif

fd_set readfds;

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
static size_t socket_max_client_packet = 24576;

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

#ifdef SEND_SHORTLIST
int send_shortlist_array[FD_SETSIZE];// we only support FD_SETSIZE sockets, limit the array to that
int send_shortlist_count = 0;// how many fd's are in the shortlist
uint32 send_shortlist_set[(FD_SETSIZE+31)/32];// to know if specific fd's are already in the shortlist
#endif

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse);

#ifndef MINICORE
	int ip_rules = 1;
	static int connect_check(uint32 ip);
#endif

const char* error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/*======================================
 * CORE : Default processing functions
 *--------------------------------------*/
int null_recv(int fd) { return 0; }
int null_send(int fd) { return 0; }
int null_parse(int fd) { return 0; }

ParseFunc default_func_parse = null_parse;

void set_defaultparse(ParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}

/*======================================
 * CORE : Socket options
 *--------------------------------------*/
void set_nonblocking(int fd, unsigned long yes)
{
	// FIONBIO Use with a nonzero argp parameter to enable the nonblocking mode of socket s.
	// The argp parameter is zero if nonblocking is to be disabled.
	if( sIoctl(fd, FIONBIO, &yes) != 0 )
		ShowError("set_nonblocking: Failed to set socket #%d to non-blocking mode (%s) - Please report this!!!\n", fd, error_msg());
}

void setsocketopts(int fd, struct hSockOpt *opt) {
	int yes = 1; // reuse fix
	struct linger lopt;

#if !defined(WIN32)
	// set SO_REAUSEADDR to true, unix only. on windows this option causes
	// the previous owner of the socket to give up, which is not desirable
	// in most cases, neither compatible with unix.
	if (sSetsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&yes,sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set SO_REUSEADDR mode for connection #%d!\n", fd);
#ifdef SO_REUSEPORT
	if (sSetsockopt(fd,SOL_SOCKET,SO_REUSEPORT,(char *)&yes,sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set SO_REUSEPORT mode for connection #%d!\n", fd);
#endif // SO_REUSEPORT
#endif // WIN32

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	if (sSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes)))
		ShowWarning("setsocketopts: Unable to set TCP_NODELAY mode for connection #%d!\n", fd);

	if( opt && opt->setTimeo ) {
		struct timeval timeout;

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		if (sSetsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)))
			ShowWarning("setsocketopts: Unable to set SO_RCVTIMEO for connection #%d!\n", fd);
		if (sSetsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,(char *)&timeout,sizeof(timeout)))
			ShowWarning("setsocketopts: Unable to set SO_SNDTIMEO for connection #%d!\n", fd);
	}

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(http://msdn.microsoft.com/library/default.asp?url=/library/en-us/winsock/winsock/closesocket_2.asp)
	lopt.l_onoff = 0; // SO_DONTLINGER
	lopt.l_linger = 0; // Do not care
	if( sSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&lopt, sizeof(lopt)) )
		ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection #%d!\n", fd);

#ifdef TCP_THIN_LINEAR_TIMEOUTS
    if (sSetsockopt(fd, IPPROTO_TCP, TCP_THIN_LINEAR_TIMEOUTS, (char *)&yes, sizeof(yes)))
	    ShowWarning("setsocketopts: Unable to set TCP_THIN_LINEAR_TIMEOUTS mode for connection #%d!\n", fd);
#endif
#ifdef TCP_THIN_DUPACK
    if (sSetsockopt(fd, IPPROTO_TCP, TCP_THIN_DUPACK, (char *)&yes, sizeof(yes)))
	    ShowWarning("setsocketopts: Unable to set TCP_THIN_DUPACK mode for connection #%d!\n", fd);
#endif
}

/*======================================
 * CORE : Socket Sub Function
 *--------------------------------------*/
void set_eof(int fd)
{
	if (sockt->session_is_active(fd)) {
#ifdef SEND_SHORTLIST
		// Add this socket to the shortlist for eof handling.
		send_shortlist_add_fd(fd);
#endif
		sockt->session[fd]->flag.eof = 1;
	}
}

int recv_to_fifo(int fd)
{
	ssize_t len;

	if (!sockt->session_is_active(fd))
		return -1;

	len = sRecv(fd, (char *) sockt->session[fd]->rdata + sockt->session[fd]->rdata_size, (int)RFIFOSPACE(fd), 0);

	if( len == SOCKET_ERROR )
	{//An exception has occurred
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("recv_to_fifo: %s, closing connection #%d\n", error_msg(), fd);
			sockt->eof(fd);
		}
		return 0;
	}

	if( len == 0 )
	{//Normal connection end.
		sockt->eof(fd);
		return 0;
	}

	sockt->session[fd]->rdata_size += len;
	sockt->session[fd]->rdata_tick = sockt->last_tick;
#ifdef SHOW_SERVER_STATS
	socket_data_i += len;
	socket_data_qi += len;
	if (!sockt->session[fd]->flag.server)
	{
		socket_data_ci += len;
	}
#endif
	return 0;
}

int send_from_fifo(int fd)
{
	ssize_t len;

	if (!sockt->session_is_valid(fd))
		return -1;

	if( sockt->session[fd]->wdata_size == 0 )
		return 0; // nothing to send

	len = sSend(fd, (const char *) sockt->session[fd]->wdata, (int)sockt->session[fd]->wdata_size, MSG_NOSIGNAL);

	if( len == SOCKET_ERROR )
	{//An exception has occurred
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("send_from_fifo: %s, ending connection #%d\n", error_msg(), fd);
#ifdef SHOW_SERVER_STATS
			socket_data_qo -= sockt->session[fd]->wdata_size;
#endif
			sockt->session[fd]->wdata_size = 0; //Clear the send queue as we can't send anymore. [Skotlex]
			sockt->eof(fd);
		}
		return 0;
	}

	if( len > 0 )
	{
		// some data could not be transferred?
		// shift unsent data to the beginning of the queue
		if( (size_t)len < sockt->session[fd]->wdata_size )
			memmove(sockt->session[fd]->wdata, sockt->session[fd]->wdata + len, sockt->session[fd]->wdata_size - len);

		sockt->session[fd]->wdata_size -= len;
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if (!sockt->session[fd]->flag.server)
		{
			socket_data_co += len;
		}
#endif
	}

	return 0;
}

/// Best effort - there's no warranty that the data will be sent.
void flush_fifo(int fd)
{
	if(sockt->session[fd] != NULL)
		sockt->session[fd]->func_send(fd);
}

void flush_fifos(void)
{
	int i;
	for(i = 1; i < sockt->fd_max; i++)
		sockt->flush(i);
}

/*======================================
 * CORE : Connection functions
 *--------------------------------------*/
int connect_client(int listen_fd) {
	int fd;
	struct sockaddr_in client_address;
	socklen_t len;

	len = sizeof(client_address);

	fd = sAccept(listen_fd, (struct sockaddr*)&client_address, &len);
	if ( fd == -1 ) {
		ShowError("connect_client: accept failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 ) { // reserved
		ShowError("connect_client: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE ) { // socket number too big
		ShowError("connect_client: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,NULL);
	sockt->set_nonblocking(fd, 1);

#ifndef MINICORE
	if( ip_rules && !connect_check(ntohl(client_address.sin_addr.s_addr)) ) {
		sockt->close(fd);
		return -1;
	}
#endif

	if( sockt->fd_max <= fd ) sockt->fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	sockt->session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);

	return fd;
}

int make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address = { 0 };
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if( fd == -1 ) {
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		exit(EXIT_FAILURE);
	}
	if( fd == 0 ) { // reserved
		ShowError("make_listen_bind: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE ) { // socket number too big
		ShowError("make_listen_bind: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,NULL);
	sockt->set_nonblocking(fd, 1);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	result = sBind(fd, (struct sockaddr*)&server_address, sizeof(server_address));
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: bind failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}
	result = sListen(fd,5);
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: listen failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}

	if(sockt->fd_max <= fd) sockt->fd_max = fd + 1;
	sFD_SET(fd, &readfds);

	create_session(fd, connect_client, null_send, null_parse);
	sockt->session[fd]->client_addr = 0; // just listens
	sockt->session[fd]->rdata_tick = 0; // disable timeouts on this socket

	return fd;
}

int make_connection(uint32 ip, uint16 port, struct hSockOpt *opt) {
	struct sockaddr_in remote_address = { 0 };
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if (fd == -1) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 ) {// reserved
		ShowError("make_connection: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE ) {// socket number too big
		ShowError("make_connection: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,opt);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if( !( opt && opt->silent ) )
		ShowStatus("Connecting to %d.%d.%d.%d:%i\n", CONVIP(ip), port);

	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));
	if( result == SOCKET_ERROR ) {
		if( !( opt && opt->silent ) )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());
		sockt->close(fd);
		return -1;
	}
	//Now the socket can be made non-blocking. [Skotlex]
	sockt->set_nonblocking(fd, 1);

	if (sockt->fd_max <= fd) sockt->fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	sockt->session[fd]->client_addr = ntohl(remote_address.sin_addr.s_addr);

	return fd;
}

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse)
{
	CREATE(sockt->session[fd], struct socket_data, 1);
	CREATE(sockt->session[fd]->rdata, unsigned char, RFIFO_SIZE);
	CREATE(sockt->session[fd]->wdata, unsigned char, WFIFO_SIZE);
	sockt->session[fd]->max_rdata  = RFIFO_SIZE;
	sockt->session[fd]->max_wdata  = WFIFO_SIZE;
	sockt->session[fd]->func_recv  = func_recv;
	sockt->session[fd]->func_send  = func_send;
	sockt->session[fd]->func_parse = func_parse;
	sockt->session[fd]->rdata_tick = sockt->last_tick;
	sockt->session[fd]->session_data = NULL;
	sockt->session[fd]->hdata = NULL;
	return 0;
}

static void delete_session(int fd)
{
	if (sockt->session_is_valid(fd)) {
#ifdef SHOW_SERVER_STATS
		socket_data_qi -= sockt->session[fd]->rdata_size - sockt->session[fd]->rdata_pos;
		socket_data_qo -= sockt->session[fd]->wdata_size;
#endif
		aFree(sockt->session[fd]->rdata);
		aFree(sockt->session[fd]->wdata);
		if( sockt->session[fd]->session_data )
			aFree(sockt->session[fd]->session_data);
		HPM->data_store_destroy(&sockt->session[fd]->hdata);
		aFree(sockt->session[fd]);
		sockt->session[fd] = NULL;
	}
}

int realloc_fifo(int fd, unsigned int rfifo_size, unsigned int wfifo_size)
{
	if (!sockt->session_is_valid(fd))
		return 0;

	if( sockt->session[fd]->max_rdata != rfifo_size && sockt->session[fd]->rdata_size < rfifo_size) {
		RECREATE(sockt->session[fd]->rdata, unsigned char, rfifo_size);
		sockt->session[fd]->max_rdata  = rfifo_size;
	}

	if( sockt->session[fd]->max_wdata != wfifo_size && sockt->session[fd]->wdata_size < wfifo_size) {
		RECREATE(sockt->session[fd]->wdata, unsigned char, wfifo_size);
		sockt->session[fd]->max_wdata  = wfifo_size;
	}
	return 0;
}

int realloc_writefifo(int fd, size_t addition)
{
	size_t newsize;

	if (!sockt->session_is_valid(fd)) // might not happen
		return 0;

	if (sockt->session[fd]->wdata_size + addition  > sockt->session[fd]->max_wdata) {
		// grow rule; grow in multiples of WFIFO_SIZE
		newsize = WFIFO_SIZE;
		while( sockt->session[fd]->wdata_size + addition > newsize ) newsize += WFIFO_SIZE;
	} else if (sockt->session[fd]->max_wdata >= (size_t)2*(sockt->session[fd]->flag.server?FIFOSIZE_SERVERLINK:WFIFO_SIZE)
	       && (sockt->session[fd]->wdata_size+addition)*4 < sockt->session[fd]->max_wdata
	) {
		// shrink rule, shrink by 2 when only a quarter of the fifo is used, don't shrink below nominal size.
		newsize = sockt->session[fd]->max_wdata / 2;
	} else {
		// no change
		return 0;
	}

	RECREATE(sockt->session[fd]->wdata, unsigned char, newsize);
	sockt->session[fd]->max_wdata  = newsize;

	return 0;
}

/// advance the RFIFO cursor (marking 'len' bytes as processed)
int rfifoskip(int fd, size_t len)
{
	struct socket_data *s;

	if (!sockt->session_is_active(fd))
		return 0;

	s = sockt->session[fd];

	if (s->rdata_size < s->rdata_pos + len) {
		ShowError("RFIFOSKIP: skipped past end of read buffer! Adjusting from %"PRIuS" to %"PRIuS" (session #%d)\n", len, RFIFOREST(fd), fd);
		len = RFIFOREST(fd);
	}

	s->rdata_pos = s->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif
	return 0;
}

/// advance the WFIFO cursor (marking 'len' bytes for sending)
int wfifoset(int fd, size_t len)
{
	size_t newreserve;
	struct socket_data* s = sockt->session[fd];

	if (!sockt->session_is_valid(fd) || s->wdata == NULL)
		return 0;

	// we have written len bytes to the buffer already before calling WFIFOSET
	if (s->wdata_size+len > s->max_wdata) {
		// actually there was a buffer overflow already
		uint32 ip = s->client_addr;
		ShowFatalError("WFIFOSET: Write Buffer Overflow. Connection %d (%d.%d.%d.%d) has written %u bytes on a %u/%u bytes buffer.\n", fd, CONVIP(ip), (unsigned int)len, (unsigned int)s->wdata_size, (unsigned int)s->max_wdata);
		ShowDebug("Likely command that caused it: 0x%x\n", (*(uint16*)(s->wdata + s->wdata_size)));
		// no other chance, make a better fifo model
		exit(EXIT_FAILURE);
	}

	if( len > 0xFFFF )
	{
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowFatalError("WFIFOSET: Packet 0x%x is too big. (len=%u, max=%u)\n", (*(uint16*)(s->wdata + s->wdata_size)), (unsigned int)len, 0xFFFF);
		exit(EXIT_FAILURE);
	}
	else if( len == 0 )
	{
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET: Attempted to send zero-length packet, most likely 0x%04x (please report this).\n", WFIFOW(fd,0));
		return 0;
	}

	if( !s->flag.server ) {

		if (len > socket_max_client_packet) { // see declaration of socket_max_client_packet for details
			ShowError("WFIFOSET: Dropped too large client packet 0x%04x (length=%"PRIuS", max=%"PRIuS").\n",
			          WFIFOW(fd,0), len, socket_max_client_packet);
			return 0;
		}

	}
	// Gepard Shield
	if (is_gepard_active == true && SERVER_TYPE != SERVER_TYPE_CHAR)
	{
		gepard_process_packet(fd, s->wdata + s->wdata_size, len, &s->send_crypt);
	}
	// Gepard Shield
	s->wdata_size += len;

#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif
	//If the interserver has 200% of its normal size full, flush the data.
	if( s->flag.server && s->wdata_size >= 2*FIFOSIZE_SERVERLINK )
		sockt->flush(fd);

	// always keep a WFIFO_SIZE reserve in the buffer
	// For inter-server connections, let the reserve be 1/4th of the link size.
	newreserve = s->flag.server ? FIFOSIZE_SERVERLINK / 4 : WFIFO_SIZE;

	// readjust the buffer to include the chosen reserve
	sockt->realloc_writefifo(fd, newreserve);

#ifdef SEND_SHORTLIST
	send_shortlist_add_fd(fd);
#endif

	return 0;
}

int do_sockets(int next)
{
	fd_set rfd;
	struct timeval timeout;
	int ret,i;

	// PRESEND Timers are executed before do_sendrecv and can send packets and/or set sessions to eof.
	// Send remaining data and process client-side disconnects here.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < sockt->fd_max; i++)
	{
		if(!sockt->session[fd]
			continue;

		if(sockt->session[fd]>wdata_size)
			sockt->session[fd]>func_send(i);
	}
#endif

	// can timeout until the next tick
	timeout.tv_sec  = next/1000;
	timeout.tv_usec = next%1000*1000;

	memcpy(&rfd, &readfds, sizeof(rfd));
	ret = sSelect(sockt->fd_max, &rfd, NULL, NULL, &timeout);

	if( ret == SOCKET_ERROR )
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: select() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}

	sockt->last_tick = time(NULL);

#if defined(WIN32)
	// on windows, enumerating all members of the fd_set is way faster if we access the internals
	for( i = 0; i < (int)rfd.fd_count; ++i )
	{
		int fd = sock2fd(rfd.fd_array[i]);
		if( sockt->session[fd] )
			sockt->session[fd]->func_recv(fd);
	}
#else
	// otherwise assume that the fd_set is a bit-array and enumerate it in a standard way
	for( i = 1; ret && i < sockt->fd_max; ++i )
	{
		if(sFD_ISSET(i,&rfd) && sockt->session[i])
		{
			sockt->session[i]->func_recv(i);
			--ret;
		}
	}
#endif

	// POSTSEND Send remaining data and handle eof sessions.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < sockt->fd_max; i++)
	{
		if(!sockt->session[i])
			continue;

		if(sockt->session[i]->wdata_size)
			sockt->session[i]->func_send(i);

		if (sockt->session[i]->flag.eof) { //func_send can't free a session, this is safe.
			//Finally, even if there is no data to parse, connections signaled eof should be closed, so we call parse_func [Skotlex]
			sockt->session[i]->func_parse(i); //This should close the session immediately.
		}
	}
#endif

	// parse input data on each socket
	for(i = 1; i < sockt->fd_max; i++)
	{
		if(!sockt->session[i])
			continue;

		if (sockt->session[i]->rdata_tick && DIFF_TICK(sockt->last_tick, sockt->session[i]->rdata_tick) > sockt->stall_time) {
			if( sockt->session[i]->flag.server ) {/* server is special */
				if( sockt->session[i]->flag.ping != 2 )/* only update if necessary otherwise it'd resend the ping unnecessarily */
					sockt->session[i]->flag.ping = 1;
			} else {
				ShowInfo("Session #%d timed out\n", i);
				sockt->eof(i);
			}
		}

#ifdef __clang_analyzer__
		// Let Clang's static analyzer know this never happens (it thinks it might because of a NULL check in session_is_valid)
		if (!sockt->session[i]) continue;
#endif // __clang_analyzer__
		sockt->session[i]->func_parse(i);

		if(!sockt->session[i])
			continue;

		RFIFOFLUSH(i);
		// after parse, check client's RFIFO size to know if there is an invalid packet (too big and not parsed)
		if (sockt->session[i]->rdata_size == sockt->session[i]->max_rdata) {
			sockt->eof(i);
			continue;
		}
	}

#ifdef SHOW_SERVER_STATS
	if (sockt->last_tick != socket_data_last_tick)
	{
		char buf[1024];

		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., iMalloc->usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif
		socket_data_last_tick = sockt->last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif

	return 0;
}

//////////////////////////////
#ifndef MINICORE
//////////////////////////////
// IP rules and DDoS protection

typedef struct connect_history {
	uint32 ip;
	int64 tick;
	int count;
	unsigned ddos : 1;
} ConnectHistory;

typedef struct access_control {
	uint32 ip;
	uint32 mask;
} AccessControl;

enum aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static AccessControl* access_allow = NULL;
static AccessControl* access_deny = NULL;
static int access_order    = ACO_DENY_ALLOW;
static int access_allownum = 0;
static int access_denynum  = 0;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
DBMap *connect_history = NULL;

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %d.%d.%d.%d %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	ConnectHistory* hist = NULL;
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for( i=0; i < access_allownum; ++i ){
		if (SUBNET_MATCH(ip, access_allow[i].ip, access_allow[i].mask)) {
			if( access_debug ){
				ShowInfo("connect_check: Found match from allow list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_allow[i].ip),
					CONVIP(access_allow[i].mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for( i=0; i < access_denynum; ++i ){
		if (SUBNET_MATCH(ip, access_deny[i].ip, access_deny[i].mask)) {
			if( access_debug ){
				ShowInfo("connect_check: Found match from deny list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_deny[i].ip),
					CONVIP(access_deny[i].mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
		case ACO_DENY_ALLOW:
		default:
			if( is_denyip )
				connect_ok = 0; // Reject
			else if( is_allowip )
				connect_ok = 2; // Unconditional Accept
			else
				connect_ok = 1; // Accept
			break;
		case ACO_ALLOW_DENY:
			if( is_allowip )
				connect_ok = 2; // Unconditional Accept
			else if( is_denyip )
				connect_ok = 0; // Reject
			else
				connect_ok = 1; // Accept
			break;
		case ACO_MUTUAL_FAILURE:
			if( is_allowip && !is_denyip )
				connect_ok = 2; // Unconditional Accept
			else
				connect_ok = 0; // Reject
			break;
	}

	// Inspect connection history
	if( ( hist = uidb_get(connect_history, ip)) ) { //IP found
		if( hist->ddos ) {// flagged as DDoS
			return (connect_ok == 2 ? 1 : 0);
		} else if( DIFF_TICK(timer->gettick(),hist->tick) < ddos_interval ) {// connection within ddos_interval
				hist->tick = timer->gettick();
				if( ++hist->count >= ddos_count ) {// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %d.%d.%d.%d!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
		} else {// not within ddos_interval, clear data
			hist->tick  = timer->gettick();
			hist->count = 0;
			return connect_ok;
		}
	}
	// IP not found, add to history
	CREATE(hist, ConnectHistory, 1);
	hist->ip   = ip;
	hist->tick = timer->gettick();
	uidb_put(connect_history, ip, hist);
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static int connect_check_clear(int tid, int64 tick, int id, intptr_t data) {
	int clear = 0;
	int list  = 0;
	ConnectHistory *hist = NULL;
	DBIterator *iter;

	if( !db_size(connect_history) )
		return 0;

	iter = db_iterator(connect_history);

	for( hist = dbi_first(iter); dbi_exists(iter); hist = dbi_next(iter) ){
		if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
			(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				uidb_remove(connect_history, hist->ip);
				clear++;
			}
		list++;
 	}
	dbi_destroy(iter);

	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}

	return list;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
int access_ipmask(const char* str, AccessControl* acc)
{
	uint32 ip;
	uint32 mask;

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%u.%u.%u.%u/%u.%u.%u.%u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%u.%u.%u.%u/%u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%u.%u.%u.%u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%d.%d.%d.%d mask:%d.%d.%d.%d\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}
//////////////////////////////
#endif
//////////////////////////////

int socket_config_read(const char* cfgName)
{
	char line[1024],w1[1024],w2[1024];
	FILE *fp;

	fp = fopen(cfgName, "r");
	if(fp == NULL) {
		ShowError("File not found: %s\n", cfgName);
		return 1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if(line[0] == '/' && line[1] == '/')
			continue;
		if (sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		if (!strcmpi(w1, "stall_time")) {
			sockt->stall_time = atoi(w2);
			if( sockt->stall_time < 3 )
				sockt->stall_time = 3;/* a minimum is required to refrain it from killing itself */
		}
#ifndef MINICORE
		else if (!strcmpi(w1, "enable_ip_rules")) {
			ip_rules = config_switch(w2);
		} else if (!strcmpi(w1, "order")) {
			if (!strcmpi(w2, "deny,allow"))
				access_order = ACO_DENY_ALLOW;
			else if (!strcmpi(w2, "allow,deny"))
				access_order = ACO_ALLOW_DENY;
			else if (!strcmpi(w2, "mutual-failure"))
				access_order = ACO_MUTUAL_FAILURE;
		} else if (!strcmpi(w1, "allow")) {
			RECREATE(access_allow, AccessControl, access_allownum+1);
			if (access_ipmask(w2, &access_allow[access_allownum]))
				++access_allownum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		} else if (!strcmpi(w1, "deny")) {
			RECREATE(access_deny, AccessControl, access_denynum+1);
			if (access_ipmask(w2, &access_deny[access_denynum]))
				++access_denynum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		}
		else if (!strcmpi(w1,"ddos_interval"))
			ddos_interval = atoi(w2);
		else if (!strcmpi(w1,"ddos_count"))
			ddos_count = atoi(w2);
		else if (!strcmpi(w1,"ddos_autoreset"))
			ddos_autoreset = atoi(w2);
		else if (!strcmpi(w1,"debug"))
			access_debug = config_switch(w2);
		else if (!strcmpi(w1,"socket_max_client_packet"))
			socket_max_client_packet = strtoul(w2, NULL, 0);
#endif
		else if (!strcmpi(w1, "import"))
			socket_config_read(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}

void socket_final(void)
{
	int i;
#ifndef MINICORE
	if( connect_history )
		db_destroy(connect_history);
	if( access_allow )
		aFree(access_allow);
	if( access_deny )
		aFree(access_deny);
#endif

	for( i = 1; i < sockt->fd_max; i++ )
		if(sockt->session[i])
			sockt->close(i);

	// sockt->session[0]
	aFree(sockt->session[0]->rdata);
	aFree(sockt->session[0]->wdata);
	aFree(sockt->session[0]);

	aFree(sockt->session);

	VECTOR_CLEAR(sockt->lan_subnets);
	VECTOR_CLEAR(sockt->allowed_ips);
	VECTOR_CLEAR(sockt->trusted_ips);
}

/// Closes a socket.
void socket_close(int fd)
{
	if( fd <= 0 ||fd >= FD_SETSIZE )
		return;// invalid

	sockt->flush(fd); // Try to send what's left (although it might not succeed since it's a nonblocking socket)
	sFD_CLR(fd, &readfds);// this needs to be done before closing the socket
	sShutdown(fd, SHUT_RDWR); // Disallow further reads/writes
	sClose(fd); // We don't really care if these closing functions return an error, we are just shutting down and not reusing this socket.
	if (sockt->session[fd]) delete_session(fd);
}

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
int socket_getips(uint32* ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if (gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR) {
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		} else {
			u_long** a;
			struct hostent *hent =gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for (; num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);
		if (fd == -1) {
			ShowError("socket_getips: Unable to create a socket!\n");
			return 0;
		}

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if (sIoctl(fd, SIOCGIFCONF, &ic) == -1) {
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			sClose(fd);
			return 0;
		} else {
			int pos;
			for (pos = 0; pos < ic.ifc_len && num < max; ) {
				struct ifreq *ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in *a = (struct sockaddr_in*) &(ir->ifr_addr);
				if (a->sin_family == AF_INET) {
					ad = ntohl(a->sin_addr.s_addr);
					if (ad != INADDR_LOOPBACK && ad != INADDR_ANY)
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

void socket_init(void)
{
	char *SOCKET_CONF_FILENAME = "conf/packet.conf";
	uint64 rlim_cur = FD_SETSIZE;

#ifdef WIN32
	{// Start up windows networking
		WSADATA wsaData;
		WORD wVersionRequested = MAKEWORD(2, 0);
		if( WSAStartup(wVersionRequested, &wsaData) != 0 )
		{
			ShowError("socket_init: WinSock not available!\n");
			return;
		}
		if( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0 )
		{
			ShowError("socket_init: WinSock version mismatch (2.0 or compatible required)!\n");
			return;
		}
	}
#elif defined(HAVE_SETRLIMIT) && !defined(CYGWIN)
	// NOTE: getrlimit and setrlimit have bogus behavior in cygwin.
	//       "Number of fds is virtually unlimited in cygwin" (sys/param.h)
	{// set socket limit to FD_SETSIZE
		struct rlimit rlp;
		if( 0 == getrlimit(RLIMIT_NOFILE, &rlp) )
		{
			rlp.rlim_cur = FD_SETSIZE;
			if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
			{// failed, try setting the maximum too (permission to change system limits is required)
				rlp.rlim_max = FD_SETSIZE;
				if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
				{// failed
					const char *errmsg = error_msg();
					int rlim_ori;
					// set to maximum allowed
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_ori = (int)rlp.rlim_cur;
					rlp.rlim_cur = rlp.rlim_max;
					setrlimit(RLIMIT_NOFILE, &rlp);
					// report limit
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_cur = rlp.rlim_cur;
					ShowWarning("socket_init: failed to set socket limit to %d, setting to maximum allowed (original limit=%d, current limit=%d, maximum allowed=%d, %s).\n", FD_SETSIZE, rlim_ori, (int)rlp.rlim_cur, (int)rlp.rlim_max, errmsg);
				}
			}
		}
	}
#endif

	// Get initial local ips
	sockt->naddr_ = sockt->getips(sockt->addr_,16);

	sFD_ZERO(&readfds);
#if defined(SEND_SHORTLIST)
	memset(send_shortlist_set, 0, sizeof(send_shortlist_set));
#endif

	CREATE(sockt->session, struct socket_data *, FD_SETSIZE);

	socket_config_read(SOCKET_CONF_FILENAME);

	// Gepard Shield
	gepard_config_read();
	// Gepard Shield

	// initialize last send-receive tick
	sockt->last_tick = time(NULL);

	// sockt->session[0] is now currently used for disconnected sessions of the map server, and as such,
	// should hold enough buffer (it is a vacuum so to speak) as it is never flushed. [Skotlex]
	create_session(0, null_recv, null_send, null_parse);

#ifndef MINICORE
	// Delete old connection history every 5 minutes
	connect_history = uidb_alloc(DB_OPT_RELEASE_DATA);
	timer->add_func_list(connect_check_clear, "connect_check_clear");
	timer->add_interval(timer->gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);
#endif

	ShowInfo("Server supports up to '"CL_WHITE"%"PRId64""CL_RESET"' concurrent connections.\n", rlim_cur);
}

bool session_is_valid(int fd)
{
	return ( fd > 0 && fd < FD_SETSIZE && sockt->session[fd] != NULL );
}

bool session_is_active(int fd)
{
	return ( sockt->session_is_valid(fd) && !sockt->session[fd]->flag.eof );
}

// Resolves hostname into a numeric ip.
uint32 host2ip(const char* hostname)
{
	struct hostent* h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

/**
 * Converts a numeric ip into a dot-formatted string.
 *
 * @param ip     Numeric IP to convert.
 * @param ip_str Output buffer, optional (if provided, must have size greater or equal to 16).
 *
 * @return A pointer to the output string.
 */
const char *ip2str(uint32 ip, char *ip_str)
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
uint32 str2ip(const char* ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Necessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

/* [Ind/Hercules] - socket_datasync */
void socket_datasync(int fd, bool send) {
	struct {
		unsigned int length;/* short is not enough for some */
	} data_list[] = {
		{ sizeof(struct mmo_charstatus) },
		{ sizeof(struct quest) },
		{ sizeof(struct item) },
		{ sizeof(struct point) },
		{ sizeof(struct s_skill) },
		{ sizeof(struct status_change_data) },
		{ sizeof(struct storage_data) },
		{ sizeof(struct guild_storage) },
		{ sizeof(struct s_pet) },
		{ sizeof(struct s_mercenary) },
		{ sizeof(struct s_homunculus) },
		{ sizeof(struct s_elemental) },
		{ sizeof(struct s_friend) },
		{ sizeof(struct mail_message) },
		{ sizeof(struct mail_data) },
		{ sizeof(struct party_member) },
		{ sizeof(struct party) },
		{ sizeof(struct guild_member) },
		{ sizeof(struct guild_position) },
		{ sizeof(struct guild_alliance) },
		{ sizeof(struct guild_expulsion) },
		{ sizeof(struct guild_skill) },
		{ sizeof(struct guild) },
		{ sizeof(struct guild_castle) },
		{ sizeof(struct fame_list) },
		{ PACKETVER },
	};
	unsigned short i;
	unsigned int alen = ARRAYLENGTH(data_list);
	if( send ) {
		unsigned short p_len = ( alen * 4 ) + 4;
		WFIFOHEAD(fd, p_len);

		WFIFOW(fd, 0) = 0x2b0a;
		WFIFOW(fd, 2) = p_len;

		for( i = 0; i < alen; i++ ) {
			WFIFOL(fd, 4 + ( i * 4 ) ) = data_list[i].length;
		}

		WFIFOSET(fd, p_len);
	} else {
		for( i = 0; i < alen; i++ ) {
			if( RFIFOL(fd, 4 + (i * 4) ) != data_list[i].length ) {
				/* force the other to go wrong too so both are taken down */
				WFIFOHEAD(fd, 8);
				WFIFOW(fd, 0) = 0x2b0a;
				WFIFOW(fd, 2) = 8;
				WFIFOL(fd, 4) = 0;
				WFIFOSET(fd, 8);
				sockt->flush(fd);
				/* shut down */
				ShowFatalError("Servers are out of sync! recompile from scratch (%d)\n",i);
				exit(EXIT_FAILURE);
			}
		}
	}
}

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending or eof handling.
void send_shortlist_add_fd(int fd)
{
	int i;
	int bit;

	if (!sockt->session_is_valid(fd))
		return;// out of range

	i = fd/32;
	bit = fd%32;

	if( (send_shortlist_set[i]>>bit)&1 )
		return;// already in the list

	if (send_shortlist_count >= ARRAYLENGTH(send_shortlist_array)) {
		ShowDebug("send_shortlist_add_fd: shortlist is full, ignoring... (fd=%d shortlist.count=%d shortlist.length=%d)\n",
		          fd, send_shortlist_count, ARRAYLENGTH(send_shortlist_array));
		return;
	}

	// set the bit
	send_shortlist_set[i] |= 1<<bit;
	// Add to the end of the shortlist array.
	send_shortlist_array[send_shortlist_count++] = fd;
}

// Do pending network sends and eof handling from the shortlist.
void send_shortlist_do_sends()
{
	int i;

	for( i = send_shortlist_count-1; i >= 0; --i )
	{
		int fd = send_shortlist_array[i];
		int idx = fd/32;
		int bit = fd%32;

		// Remove fd from shortlist, move the last fd to the current position
		--send_shortlist_count;
		send_shortlist_array[i] = send_shortlist_array[send_shortlist_count];
		send_shortlist_array[send_shortlist_count] = 0;

		if( fd <= 0 || fd >= FD_SETSIZE )
		{
			ShowDebug("send_shortlist_do_sends: fd is out of range, corrupted memory? (fd=%d)\n", fd);
			continue;
		}
		if( ((send_shortlist_set[idx]>>bit)&1) == 0 )
		{
			ShowDebug("send_shortlist_do_sends: fd is not set, why is it in the shortlist? (fd=%d)\n", fd);
			continue;
		}
		send_shortlist_set[idx]&=~(1<<bit);// unset fd
		// If this session still exists, perform send operations on it and
		// check for the eof state.
		if( sockt->session[fd] )
		{
			// Send data
			if( sockt->session[fd]->wdata_size )
				sockt->session[fd]->func_send(fd);

			// If it's been marked as eof, call the parse func on it so that
			// the socket will be immediately closed.
			if( sockt->session[fd]->flag.eof )
				sockt->session[fd]->func_parse(fd);

			// If the session still exists, is not eof and has things left to
			// be sent from it we'll re-add it to the shortlist.
			if( sockt->session[fd] && !sockt->session[fd]->flag.eof && sockt->session[fd]->wdata_size )
				send_shortlist_add_fd(fd);
		}
	}
}
#endif

/**
 * Checks whether the given IP comes from LAN or WAN.
 *
 * @param[in]  ip   IP address to check.
 * @param[out] info Verbose output, if requested. Filled with the matching entry. Ignored if NULL.
 * @retval 0 if it is a WAN IP.
 * @return the appropriate LAN server address to send, if it is a LAN IP.
 */
uint32 socket_lan_subnet_check(uint32 ip, struct s_subnet *info)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(sockt->lan_subnets), i, SUBNET_MATCH(ip, VECTOR_INDEX(sockt->lan_subnets, i).ip, VECTOR_INDEX(sockt->lan_subnets, i).mask));
	if (i != VECTOR_LENGTH(sockt->lan_subnets)) {
		if (info) {
			info->ip = VECTOR_INDEX(sockt->lan_subnets, i).ip;
			info->mask = VECTOR_INDEX(sockt->lan_subnets, i).mask;
		}
		return VECTOR_INDEX(sockt->lan_subnets, i).ip;
	}
	if (info) {
		info->ip = info->mask = 0;
	}
	return 0;
}

/**
 * Checks whether the given IP is allowed to connect as a server.
 *
 * @param ip IP address to check.
 * @retval true if we allow server connections from the given IP.
 * @retval false otherwise.
 */
bool socket_allowed_ip_check(uint32 ip)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(sockt->allowed_ips), i, SUBNET_MATCH(ip, VECTOR_INDEX(sockt->allowed_ips, i).ip, VECTOR_INDEX(sockt->allowed_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->allowed_ips))
		return true;
	return sockt->trusted_ip_check(ip); // If an address is trusted, it's automatically also allowed.
}

/**
 * Checks whether the given IP is trusted and can skip ipban checks.
 *
 * @param ip IP address to check.
 * @retval true if we trust the given IP.
 * @retval false otherwise.
 */
bool socket_trusted_ip_check(uint32 ip)
{
	int i;
	ARR_FIND(0, VECTOR_LENGTH(sockt->trusted_ips), i, SUBNET_MATCH(ip, VECTOR_INDEX(sockt->trusted_ips, i).ip, VECTOR_INDEX(sockt->trusted_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->trusted_ips))
		return true;
	return false;
}

/**
 * Helper function to read a list of network.conf values.
 *
 * Entries will be appended to the variable-size array pointed to by list/count.
 *
 * @param[in]     t         The list to parse.
 * @param[in,out] list      Vector to append to. Must not be NULL (but the vector may be empty).
 * @param[in]     filename  Current filename, for output/logging reasons.
 * @param[in]     groupname Current group name, for output/logging reasons.
 * @return The amount of entries read, zero in case of errors.
 */
int socket_net_config_read_sub(config_setting_t *t, struct s_subnet_vector *list, const char *filename, const char *groupname)
{
	int i, len;
	char ipbuf[64], maskbuf[64];

	nullpo_retr(0, list);

	if (t == NULL)
		return 0;

	len = libconfig->setting_length(t);

	VECTOR_ENSURE(*list, len, 1);
	for (i = 0; i < len; ++i) {
		const char *subnet = libconfig->setting_get_string_elem(t, i);
		struct s_subnet *entry = NULL;

		if (sscanf(subnet, "%63[^:]:%63[^:]", ipbuf, maskbuf) != 2) {
			ShowWarning("Invalid IP:Subnet entry in configuration file %s: '%s' (%s)\n", filename, subnet, groupname);
			continue;
		}
		VECTOR_PUSHZEROED(*list);
		entry = &VECTOR_LAST(*list);
		entry->ip = sockt->str2ip(ipbuf);
		entry->mask = sockt->str2ip(maskbuf);
	}
	return (int)VECTOR_LENGTH(*list);
}

/**
 * Reads the network configuration file.
 *
 * @param filename The filename to read from.
 */
void socket_net_config_read(const char *filename)
{
	config_t network_config;
	int i;
	nullpo_retv(filename);

	if (libconfig->read_file(&network_config, filename)) {
		ShowError("LAN Support configuration file is not found: '%s'. This server won't be able to accept connections from any servers.\n", filename);
		return;
	}

	VECTOR_CLEAR(sockt->lan_subnets);
	if (sockt->net_config_read_sub(libconfig->lookup(&network_config, "lan_subnets"), &sockt->lan_subnets, filename, "lan_subnets") > 0)
		ShowStatus("Read information about %d LAN subnets.\n", (int)VECTOR_LENGTH(sockt->lan_subnets));

	VECTOR_CLEAR(sockt->trusted_ips);
	if (sockt->net_config_read_sub(libconfig->lookup(&network_config, "trusted"), &sockt->trusted_ips, filename, "trusted") > 0)
		ShowStatus("Read information about %d trusted IP ranges.\n", (int)VECTOR_LENGTH(sockt->trusted_ips));
	ARR_FIND(0, VECTOR_LENGTH(sockt->trusted_ips), i, SUBNET_MATCH(0, VECTOR_INDEX(sockt->trusted_ips, i).ip, VECTOR_INDEX(sockt->trusted_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->trusted_ips)) {
		ShowError("Using a wildcard IP range in the trusted server IPs is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your '%s' trusted list to fit your network configuration.\n", filename);
	}

	VECTOR_CLEAR(sockt->allowed_ips);
	if (sockt->net_config_read_sub(libconfig->lookup(&network_config, "allowed"), &sockt->allowed_ips, filename, "allowed") > 0)
		ShowStatus("Read information about %d allowed server IP ranges.\n", (int)VECTOR_LENGTH(sockt->allowed_ips));
	if (VECTOR_LENGTH(sockt->allowed_ips) + VECTOR_LENGTH(sockt->trusted_ips) == 0) {
		ShowError("No allowed server IP ranges configured. This server won't be able to accept connections from any char servers.\n");
	}
	ARR_FIND(0, VECTOR_LENGTH(sockt->allowed_ips), i, SUBNET_MATCH(0, VECTOR_INDEX(sockt->allowed_ips, i).ip, VECTOR_INDEX(sockt->allowed_ips, i).mask));
	if (i != VECTOR_LENGTH(sockt->allowed_ips)) {
		ShowWarning("Using a wildcard IP range in the allowed server IPs is NOT RECOMMENDED.\n");
		ShowNotice("Please edit your '%s' allowed list to fit your network configuration.\n", filename);
	}
	libconfig->destroy(&network_config);
	return;
}

void socket_defaults(void) {
	sockt = &sockt_s;

	sockt->fd_max = 0;
	/* */
	sockt->stall_time = 60;
	sockt->last_tick = 0;
	/* */
	memset(&sockt->addr_, 0, sizeof(sockt->addr_));
	sockt->naddr_ = 0;
	/* */
	VECTOR_INIT(sockt->lan_subnets);
	VECTOR_INIT(sockt->allowed_ips);
	VECTOR_INIT(sockt->trusted_ips);

	sockt->init = socket_init;
	sockt->final = socket_final;
	/* */
	sockt->perform = do_sockets;
	/* */
	sockt->datasync = socket_datasync;
	/* */
	sockt->make_listen_bind = make_listen_bind;
	sockt->make_connection = make_connection;
	sockt->realloc_fifo = realloc_fifo;
	sockt->realloc_writefifo = realloc_writefifo;
	sockt->wfifoset = wfifoset;
	sockt->rfifoskip = rfifoskip;
	sockt->close = socket_close;
	/* */
	sockt->session_is_valid = session_is_valid;
	sockt->session_is_active = session_is_active;
	/* */
	sockt->flush = flush_fifo;
	sockt->flush_fifos = flush_fifos;
	sockt->set_nonblocking = set_nonblocking;
	sockt->set_defaultparse = set_defaultparse;
	sockt->host2ip = host2ip;
	sockt->ip2str = ip2str;
	sockt->str2ip = str2ip;
	sockt->ntows = ntows;
	sockt->getips = socket_getips;
	sockt->eof = set_eof;

	sockt->lan_subnet_check = socket_lan_subnet_check;
	sockt->allowed_ip_check = socket_allowed_ip_check;
	sockt->trusted_ip_check = socket_trusted_ip_check;
	sockt->net_config_read_sub = socket_net_config_read_sub;
	sockt->net_config_read = socket_net_config_read;
}

bool is_gepard_active;
uint32 min_allowed_gepard_version;
uint32 gepard_rand_seed;

const unsigned char* shield_matrix = (const unsigned char*)

"\x6b\x1d\x81\x96\x4c\xce\xfc\x3d\x26\x8f\xc8\xcc\xc0\x86\x2a\x8a"
"\x43\x22\xe7\x25\xd7\xfb\x38\x3b\x38\x79\xe8\x9b\xdf\x8f\x25\xed"
"\x49\xd6\xcc\xd5\xf5\xc7\x51\xb9\xab\xc1\x1b\xea\x2a\xda\x50\x9a"
"\xb2\x74\x0b\x82\x37\x14\x5d\x30\x0b\xa5\x30\xb6\xcc\x74\x4f\xd5"
"\x0f\x9b\x3f\xce\x5d\x38\xa5\x79\xa0\x12\x61\x49\x0d\x1d\xa1\xd6"
"\x1a\x6c\x13\xb0\xa6\x05\xf2\xec\xcc\xb9\x9c\xc8\x1b\xdd\x6f\xd6"
"\x0f\x8d\x0f\x03\xa3\x5e\x61\x69\x56\xa0\x58\xca\xdb\x16\xdc\x22"
"\xef\x46\xe7\x18\x84\x46\x2f\x68\xb5\xaf\xde\xe0\xbf\x8f\x56\x21"
"\x61\x84\xd3\x46\x6c\x6d\x8c\x0b\x69\xc2\xa3\x29\x0c\x07\x64\x72"
"\xee\x74\xd4\xf8\x3b\x45\x6d\xae\xc0\x37\x0c\xe0\x31\x43\x78\xf4"
"\x63\x8c\x8c\xbf\x61\x8b\xd6\xf5\xb3\x80\x48\x70\x17\xa1\x3f\xd5"
"\x94\x9d\x09\x62\xb2\x60\xaf\x60\x2c\x32\x1c\x22\x6c\x25\xee\x26"
"\xb4\x64\x19\xeb\xaf\xd0\x12\xd4\x59\x16\xb2\x03\x7a\x8c\x19\xe8"
"\x23\x99\x18\xbb\xda\xeb\x19\x32\x7c\x37\x6c\x4a\x70\x58\xf6\x20"
"\x39\x22\xc0\x19\x86\x4d\x33\x63\x3d\xf4\x30\x14\x37\x63\xbf\x60"
"\x20\x77\x7a\xbe\x26\x30\xf0\xeb\xf6\x11\xbb\x1d\xc0\x6f\x71\xde"
"\x9a\x87\xab\x6c\x1c\x01\x54\xf6\x89\xc0\xf1\xad\x54\xb5\x27\x83"
"\xd6\xf5\x89\xf8\x8b\xe9\x23\x69\xa8\x3d\xae\x2b\x65\x75\x64\xf4"
"\xc2\x55\x67\xdc\xa7\x64\xb3\xf3\x2b\xd1\x90\x2b\x5b\x85\x65\x2c"
"\xd5\x8d\x85\x4b\x05\x48\xbf\x9c\x5f\xee\x4e\x7c\xe8\x66\xf5\x85"
"\x63\xf8\x64\xb7\x66\xdf\x33\xd4\x54\x36\x85\xbd\x59\x4b\xb6\x4c"
"\x6d\xe7\x13\xec\x11\xef\x7b\x87\x2f\x0d\x08\x6a\xdc\xb2\x74\x4c"
"\x6f\x37\xf9\x1b\x19\x51\x58\xa8\x78\x2c\xae\xea\xde\xef\xf7\x64"
"\x35\x5f\x37\xe6\x34\x78\xac\x44\xee\xb1\xa9\xa4\xd2\x40\x52\x15"
"\xa0\x85\xe0\xfa\x84\x0b\x4d\x11\x52\x2b\x4f\x0b\x84\x54\x2e\x8d"
"\x86\x88\xdf\x17\x72\xed\xd0\x7e\xb9\x2b\x6a\x2e\x64\x68\xa1\x41"
"\x72\x91\x37\xa0\xf1\xd3\xe0\xc4\x5d\xd8\x0d\x4b\x60\x4b\xfd\xf1"
"\xfe\x28\xd9\x30\xd8\xcf\x87\xf4\xed\xfc\xe0\x5d\x2c\x77\x9d\x46"
"\x24\xba\xfb\xa5\xac\xe4\x03\x0d\x5c\x93\xf2\xab\x93\x9a\xb4\x52"
"\x03\xb6\x5b\xb6\xf4\x93\x93\xfe\xb0\x5c\x89\xdb\xc9\x2e\xa1\x2d"
"\xba\x93\x96\x7b\x06\x6c\xca\xc8\x54\xea\xee\x81\x3c\x7e\xbe\x7f"
"\x37\xe2\xf9\x84\x58\x20\x5d\x82\xe6\xb4\xc5\x2a\xe0\xc1\xaf\x14"
"\xfd\x63\xcf\x65\x52\x0d\xf2\xeb\x0d\x23\x54\xf4\x83\x26\xb1\xe3"
"\x05\x8d\xb0\x47\x9b\x51\xf1\xfc\xbd\xa3\x59\x9b\x1a\xdc\xec\x2b"
"\xfa\x26\xd4\x7a\xea\xdb\x57\x7a\x14\xb6\x58\x04\x11\x33\xc2\x78"
"\x1c\xcc\xe0\x02\xd8\x78\x7f\xfd\xa1\x7d\xec\xd3\x1f\x1b\xa0\xb8"
"\x80\x0c\x38\xa6\xab\xe2\xfb\x8e\x3c\xcf\x95\xfd\x92\xbd\xcc\x4d"
"\x6e\xe9\x4c\x89\xad\x58\xdb\xaa\x49\xc6\x8b\xd0\x22\x0d\x38\x95"
"\x24\xf7\xed\x2c\x75\xa1\x84\x58\x18\x50\x8b\x88\x3b\xd0\xcf\x85"
"\x31\x62\x1b\x07\x3e\x29\x7d\xb9\xa9\x3c\xa7\xdf\xd4\xb8\xc5\x2f"
"\x3d\x01\xd0\x9b\x2e\x88\x3d\x98\x83\xcc\x1b\x9c\xbd\x6b\x6d\xd7"
"\x5e\xe7\x58\x7a\xaf\x18\x7f\x78\x7d\x4a\x95\xa3\xee\x16\x7d\x06"
"\xe7\xf3\x9c\xdc\xbc\xfd\x13\x27\x98\x8d\x0c\x86\x56\x80\xec\x11"
"\x36\xde\xf3\x33\x2e\xc3\x24\xc8\x46\x14\x0c\x93\x2d\x14\x38\xb0"
"\x04\x4f\xf3\xae\x8e\x5d\x97\xec\xbb\x8e\x08\xe7\x42\x76\xb9\x0f"
"\x38\x62\x40\x58\xe6\x40\x4e\x1b\x44\x70\xa8\x7a\xce\x11\x73\x57"
"\x36\x46\x5c\x9e\x93\x71\x80\x67\x10\x01\x9c\xb3\xc2\xa8\x62\x45"
"\x2d\x40\x76\x63\x8d\x16\x05\x7b\x81\xe9\x6b\x76\x17\x65\xce\xb7"
"\xe6\xc1\x3d\x10\xc1\x80\x28\x2b\x7e\x49\x3e\x34\x9c\xe6\x99\x3c"
"\x1d\x78\xaf\xa1\x59\xc1\x75\x84\xc5\xbe\x38\x7b\x4d\x56\x8f\x23"
"\xc1\x5c\xe6\x3c\x90\x3d\x8c\x5d\xb5\x7f\x42\x85\x1b\x73\xb6\x0e"
"\x56\x41\xec\x36\x03\xb2\x6e\xe5\xa3\x62\x59\x4e\x3f\x24\x1f\x7e"
"\x37\x65\x09\x2e\x7d\x53\xcf\xb7\x26\x71\xe2\x99\x0b\x05\x35\x69"
"\x6c\x83\x91\x15\x4b\xcd\x64\x64\xeb\x79\xf8\x0b\xba\xfd\x8b\x44"
"\xfa\xe0\xb9\xc4\x08\x60\xb6\x89\x84\x1d\xbe\x34\xbe\x48\xb1\x92"
"\xb4\x5e\xe3\x89\xf2\xe9\x6f\x59\x36\x60\xa9\xa0\x92\x88\x03\x22"
"\x06\x86\x71\xb5\x36\xf6\x2c\x34\xca\x3a\xd7\x6d\x8a\x5a\xf1\x62"
"\xc8\x22\x11\xb0\xc1\x53\xcb\x30\xde\x25\x5d\xd1\xa0\xde\xdc\xd3"
"\x13\x41\x8e\x87\x11\x1b\xbd\x2f\xb4\xae\x15\x33\x48\x4f\xda\x40"
"\x88\xd3\x26\x7c\x02\xc9\xd7\x69\x04\x89\xee\x35\xbe\x8c\x8f\x75"
"\x24\xb1\xd1\x16\x23\xc8\x9e\x82\x45\x19\xc0\xc5\xd7\x2e\x78\xae"
"\x93\xae\x19\xb1\x03\x82\x98\x18\x09\x84\x18\xb4\xcd\x13\xba\x2d"
"\x7c\x2a\xe0\x91\xfe\x6e\x22\xce\x41\x48\x09\xba\x98\x71\x78\xc0"
"\x52\x9e\xbf\x6c\x16\xa4\xb6\xe5\x15\xc0\xfb\x11\xb1\x67\x1d\xd9"
"\xa3\x32\x46\xfd\x38\xeb\xc3\x46\x30\x41\x80\x7a\x70\x08\x2f\x9b"
"\x6d\xc5\xd4\x18\x14\xcb\x7c\x8f\x13\x9d\x9d\x5b\xd0\x72\x1d\xea"
"\x67\x06\xec\xb2\xe7\x19\x22\xad\x60\x3d\x9e\xc1\xc9\x56\x13\xfb"
"\x54\x79\x79\xf7\xd4\x89\xda\x63\x32\x2c\x65\xfa\x18\x90\x43\x66"
"\xd5\x15\xa7\xda\x2a\x40\x7d\x5f\x64\x28\xbb\x20\x12\x32\x3e\x31"
"\xb8\x44\xb0\x21\xb8\xe0\xe4\x47\xe5\xb3\x20\xa9\x75\x93\x3c\x66"
"\xc4\x82\x2d\xf6\xa0\x1d\x3d\x4b\x0e\xa2\x18\xfb\xba\x66\x70\x9e"
"\x10\x62\x61\xfc\xa2\x49\xd3\xb3\x65\x2f\xfd\x78\x5e\xc0\x58\x17"
"\xca\xa5\x14\xda\x6f\x64\x6a\xf1\xf9\x81\x54\x8d\xb8\x32\x8c\xbb"
"\x15\xc6\x57\x4b\xf7\xaf\x03\x33\x2c\xca\x13\xc7\xc9\xd0\x8d\xb9"
"\xc5\x8b\x5c\x2e\x3f\x3b\xb2\xeb\x02\xcc\x78\xe1\x07\xc9\x19\x12"
"\xc5\x95\x41\x1b\xa4\x74\x70\xe7\xf7\xeb\x58\xcf\x33\x71\xf3\x24"
"\xd5\xf1\xe4\xeb\xbc\xb9\xe7\x60\xca\x41\x6d\x58\x23\x52\xc0\x42"
"\xe4\xa8\x33\xd3\x97\xe9\x43\x05\xcd\xa8\xa9\x9b\x99\x42\xc8\x40"
"\x5d\xcc\xf5\x66\x18\x70\x01\x0f\x37\xcf\x83\x28\x0f\xe8\xd2\x22"
"\x77\x8d\xa5\x2f\xc1\x59\xc1\x53\xf2\x4a\xc7\x09\x02\x59\xec\x0a"
"\x06\xc4\x37\x3e\x06\x60\x97\x4b\x70\x9c\xeb\x58\xce\x9b\x42\x92"
"\xc8\x86\x71\xb9\x9a\x7f\x57\x2e\xf3\xcf\x58\x4b\xf3\xbe\x65\x92"
"\x3b\x33\xb6\xec\x41\x80\xe8\xfa\x64\x7f\x3d\xc5\x6c\x6c\xa5\x54"
"\x65\x08\x57\x57\x9c\x8a\x94\x87\x1f\xeb\xe0\x68\xf9\xf0\xdb\x01"
"\xad\xaa\xe4\x3e\x83\x38\xd6\x96\x44\x86\x71\x22\xf6\x53\x39\xb4"
"\xa1\xbb\x7b\x3c\xc7\xa0\xad\x62\x88\x85\xcf\x3c\xa4\xdf\x1b\x8c"
"\xd0\x6b\x18\xd1\x8e\x69\x68\x2e\x05\x71\x67\xf0\xfe\xbb\xd9\x38"
"\x92\x80\xe3\x72\x1d\x58\x79\x57\x07\x36\x75\xf4\x08\x70\x95\x05"
"\xdd\x6f\x09\x1a\xa7\xe2\x47\x63\x5f\x34\xe1\x8c\x9a\x04\x0b\xf3"
"\x12\xe6\xfc\x58\x24\xbd\xf5\x92\x35\xcc\x85\x16\xb9\xfc\xe0\xc8"
"\x4f\xe0\xd5\xe1\x97\x6c\xbf\x6d\xd0\x77\x06\xa0\x63\xfe\x75\x15"
"\x3f\xb3\x95\x9f\x66\xd0\x40\x54\xf1\xcc\x99\xf5\xd7\x51\xb4\xcd"
"\xe6\xa0\x7f\xc1\xa9\x3f\x45\x94\x9a\x19\x5f\x2e\xf5\xf4\x62\x59"
"\x7a\xe1\x61\xcc\x74\x07\x9d\x71\x61\xeb\xac\x3e\x80\xae\x6d\x1f"
"\x29\xbf\xea\xab\xaf\x09\xed\x38\xc2\x28\x5c\x0a\x75\x9f\xbf\x16"
"\xeb\x1e\xf7\xbb\xdf\xc6\x77\xd1\xea\x94\x1f\xef\x58\xca\x8d\x58"
"\x5c\x88\x62\x61\xfc\x6d\xf1\x4c\x90\x69\x4e\x5d\x86\xae\xa2\xb0"
"\x7c\xc9\xd3\x18\xbe\xeb\x56\x71\xb9\xe5\x37\xdb\x06\x4e\xb8\x2c"
"\x0e\xf5\x13\xfc\x6c\x01\x31\xd4\x91\x56\xed\xa3\xd3\x44\x41\x26"
"\xda\x7b\xd5\xe4\x2c\x48\x6d\xe0\x3a\xb0\x9b\xa9\x36\x55\xb7\xdd"
"\x8d\x36\x0f\x68\x58\xcd\xab\xeb\x98\x9a\xd2\xae\x8a\xf8\xf5\x04"
"\xf8\xfb\x40\xf6\xc7\x1e\x0e\x45\xa3\x7e\x59\x53\x97\x72\xf8\xc8"
"\xef\xad\xc9\x64\xa2\x53\x89\xc1\xb8\x18\x7c\x24\xdb\x57\xbe\xed"
"\x0d\xc7\xba\xf9\x32\x26\x32\x54\x6a\x07\x60\x29\x5e\x28\x0c\xd7"
"\x0c\xf2\x1f\x84\xb0\x02\x12\x17\x4d\x60\x4e\x7b\x7d\x5d\xc0\x1c"
"\x91\x91\xd0\x69\x15\x0d\xf4\xdc\xc9\xba\x06\xcc\xc1\x73\xa6\x8f"
"\x7f\x53\x4a\x31\x69\x40\xb5\xc3\x70\xbe\x0e\x80\xaa\xfe\xc1\xd8"
"\x44\xbf\xf1\x99\x18\xf1\x16\x3f\x43\xba\x81\x35\xfd\xbd\x21\x02"
"\x2a\x4d\x6e\xa5\xb9\xe8\x85\x30\x86\x2e\xe4\xd6\x1e\x23\xad\x05"
"\x27\x6a\x71\x2e\xea\xe8\x78\x6d\x96\xdd\xef\x2d\x53\xe9\x78\x5a"
"\x2f\x14\x10\x70\x94\xc7\xb6\xda\x33\xe0\x63\xf0\x9c\x24\x91\x91"
"\x80\xdf\x87\xa1\xc0\xf9\x26\xf1\x4d\x30\xd2\x54\x83\xcc\x4e\x55"
"\xf6\x0f\x97\xf7\xea\xa2\x23\x57\xde\xb9\x7a\x18\xe9\x52\xa0\x87"
"\xda\xa0\xcd\xc0\x50\x22\xc9\x68\x32\x6e\x0c\x9c\xd7\x2e\xe5\xc4"
"\x2f\x5b\x54\x71\x39\xab\xc9\xcb\xb7\xd1\x22\xe9\x4f\xef\x33\x80"
"\x84\x63\xc4\xaf\xd2\xcf\x33\x80\xd4\x0c\x65\xcb\x1b\x4d\x29\x8d"
"\xc5\xc6\xf6\x69\x79\x8f\xcb\x71\x2f\x76\x30\xd6\x1c\x34\xc3\x2e"
"\x8e\x91\x50\x62\x08\x69\xd6\x7e\x86\x2e\x0c\x7f\x9d\x59\x25\x28"
"\x71\x56\x94\xc0\xac\xea\xee\x96\xf9\x27\xa8\xa3\x21\x49\xef\xd1"
"\x4f\x47\xb6\xa2\xb3\x44\x4d\xbb\xdf\x31\x8e\xa3\x32\xf8\x8b\xa2"
"\x27\xc0\x27\xaa\x58\x50\x1d\x9e\x11\x18\x6b\xe7\xb3\x4f\x7b\xc3"
"\xe1\xd7\xa4\x0f\x99\x2e\x50\x24\xbb\xa3\x63\x7b\x31\xc2\x2f\x1e"
"\x26\xf0\x0b\x2e\x85\x46\xe5\x7f\x31\x32\x5f\x92\x2e\xd9\x4e\xee"
"\xa4\xc8\xa7\x99\x87\xe5\xc0\xb7\xb9\xc5\xe0\x1f\x76\xc5\x0b\xd0"
"\xec\x07\x03\xa7\x3f\xc5\x78\xc1\xdc\x13\x4f\xe2\x6d\xed\x72\xd2"
"\x38\xd1\x35\x06\x4a\xa0\x24\x0a\xbb\x90\xc5\x79\xe0\x02\xba\x03"
"\x40\x57\x33\x47\x96\x3e\x2c\x06\xd8\x0a\x68\xed\xd3\x08\x95\x81"
"\x04\xe1\xa3\x70\x34\x06\x9f\x45\x6a\x2e\xb0\x47\xd3\xed\x7e\x11";

void gepard_config_read()
{
	char* conf_name = "conf/gepard_shield.conf";
	char line[1024], w1[1024], w2[1024];

	FILE* fp = fopen(conf_name, "r");

	is_gepard_active = false;

	if (fp == NULL)
	{
		ShowError("Gepard configuration file (%s) not found. Shield disabled.\n", conf_name);
		return;
	}

	while (fgets(line, sizeof(line), fp))
	{
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if (!strcmpi(w1, "gepard_shield_enabled"))
		{
			is_gepard_active = (bool)config_switch(w2);
		}
	}

	fclose(fp);

	conf_name = "conf/gepard_version.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		min_allowed_gepard_version = 0;
		ShowError("Gepard version file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &min_allowed_gepard_version);

	fclose(fp);
}

bool gepard_process_packet(int fd, uint8* packet_data, uint32 packet_size, struct gepard_crypt_link* link)
{
	uint16 packet_id = RBUFW(packet_data, 0);

	switch (packet_id)
	{
	case CS_GEPARD_SYNC:
	{
		uint32 control_value;

		gepard_enc_dec(packet_data + 2, packet_data + 2, 4, &sockt->session[fd]->sync_crypt);

		control_value = RFIFOL(fd, 2);

		if (control_value == 0xDDCCBBAA)
		{
			sockt->session[fd]->gepard_info.sync_tick = timer->gettick();
		}

		RFIFOSKIP(fd, 6);

		return true;
	}
	break;

	case CS_LOGIN_PACKET:
	{
		if (sockt->session[fd]->gepard_info.is_init_ack_received == false)
		{
			RFIFOSKIP(fd, RFIFOREST(fd));
			gepard_init(fd, GEPARD_LOGIN);
			return true;
		}

		gepard_enc_dec(packet_data + 2, packet_data + 2, RFIFOREST(fd) - 2, link);
	}
	break;

	case CS_WHISPER_TO:
	case SC_WHISPER_FROM:
	case SC_SET_UNIT_IDLE:
	case SC_SET_UNIT_WALKING:
	{
		packet_size = RBUFW(packet_data, 2);
		gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
	}
	break;

	case CS_WALK_TO_XY:
	case CS_USE_SKILL_TO_ID:
	case CS_USE_SKILL_TO_POS:
	case SC_CHANGE_OPTION:
	case SC_STATUS_CHANGE:
	case SC_SKILL_CASTING:
	case SC_SKILL_DAMAGE:
	case SC_SKILL_NODAMAGE:
	{
		gepard_enc_dec(packet_data + 2, packet_data + 2, packet_size - 2, link);
	}
	break;

	case CS_GEPARD_INIT_ACK:
	{
		uint32 unique_id, unique_id_, shield_ver;
		uint32 init_packet_size = RFIFOW(fd, 2);

		if (init_packet_size < 16 || init_packet_size > RFIFOREST(fd))
		{
			ShowWarning("gepard_process_packet: invalid size of CS_GEPARD_INIT_ACK packet: %u\n", init_packet_size);
			set_eof(fd);
			return true;
		}

		gepard_enc_dec(packet_data + 4, packet_data + 4, init_packet_size - 4, link);

		unique_id = RFIFOL(fd, 4);
		shield_ver = RFIFOL(fd, 8);
		unique_id_ = RFIFOL(fd, 12) ^ UNIQUE_ID_XOR;

		RFIFOSKIP(fd, init_packet_size);

		if (!unique_id || !unique_id_ || unique_id != unique_id_)
		{
			WFIFOHEAD(fd, 6);
			WFIFOW(fd, 0) = SC_GEPARD_INFO;
			WFIFOL(fd, 2) = 3;
			WFIFOSET(fd, 6);
			set_eof(fd);
		}

		sockt->session[fd]->gepard_info.is_init_ack_received = true;
		sockt->session[fd]->gepard_info.unique_id = unique_id;
		sockt->session[fd]->gepard_info.gepard_shield_version = shield_ver;

		return true;
	}
	break;
	}

	return false;
}

inline void gepard_srand(unsigned int seed)
{
	gepard_rand_seed = seed;
}

inline unsigned int gepard_rand()
{
	return (((gepard_rand_seed = gepard_rand_seed * 214013L + 2531011L) >> 16) & 0x7fff);
}

void gepard_session_init(int fd, unsigned int recv_key, unsigned int send_key, unsigned int sync_key)
{
	uint32 i;
	uint8 random_1 = RAND_1_START;
	uint8 random_2 = RAND_2_START;

	sockt->session[fd]->recv_crypt.pos_1 = sockt->session[fd]->send_crypt.pos_1 = sockt->session[fd]->sync_crypt.pos_1 = POS_1_START;
	sockt->session[fd]->recv_crypt.pos_2 = sockt->session[fd]->send_crypt.pos_2 = sockt->session[fd]->sync_crypt.pos_2 = POS_2_START;
	sockt->session[fd]->recv_crypt.pos_3 = sockt->session[fd]->send_crypt.pos_3 = sockt->session[fd]->sync_crypt.pos_3 = 0;

	gepard_srand(recv_key ^ SRAND_CONST);

	for (i = 0; i < (KEY_SIZE - 1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		random_1 -= (5 * random_2) - 6;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		random_2 += (7 * random_1) - 4;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		sockt->session[fd]->recv_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;
	gepard_srand(send_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE - 1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		random_1 += (3 * random_2) - 8;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		random_2 += (9 * random_1) - 5;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		sockt->session[fd]->send_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;
	gepard_srand(sync_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE - 1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		random_1 += (3 * random_2) - 2;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		random_2 -= (2 * random_1) + 8;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE - 1)];
		sockt->session[fd]->sync_crypt.key[i] = random_1;
	}
}

void gepard_init(int fd, uint16 server_type)
{
	const uint16 init_packet_size = 20;
	uint16 recv_key = (gepard_rand() % 0xFFFF);
	uint16 send_key = (gepard_rand() % 0xFFFF);
	uint16 sync_key = (gepard_rand() % 0xFFFF);

	gepard_srand((unsigned)time(NULL) ^ clock());

	WFIFOHEAD(fd, init_packet_size);
	WFIFOW(fd, 0) = SC_GEPARD_INIT;
	WFIFOW(fd, 2) = init_packet_size;
	WFIFOW(fd, 4) = recv_key;
	WFIFOW(fd, 6) = send_key;
	WFIFOW(fd, 8) = server_type;
	WFIFOL(fd, 10) = GEPARD_ID;
	WFIFOL(fd, 14) = min_allowed_gepard_version;
	WFIFOW(fd, 18) = sync_key;
	WFIFOSET(fd, init_packet_size);

	gepard_session_init(fd, recv_key, send_key, sync_key);
}

void gepard_enc_dec(uint8* in_data, uint8* out_data, uint32 data_size, struct gepard_crypt_link* link)
{
	uint32 i;

	for (i = 0; i < data_size; ++i)
	{
		link->pos_1 += link->key[link->pos_3 % (KEY_SIZE - 1)];
		link->pos_2 += (link->pos_1 - 12) * 5;
		link->key[link->pos_2 % (KEY_SIZE - 1)] ^= link->pos_1;
		link->pos_1 -= (link->pos_2 + link->pos_3) / 6;
		link->key[link->pos_3 % (KEY_SIZE - 1)] ^= link->pos_1;
		out_data[i] = in_data[i] ^ link->pos_1;
		link->pos_1 += 4;
		link->pos_2 -= data_size % 0xFF;
		link->pos_3++;
	}
}

void gepard_send_info(int fd, unsigned short info_type, char* message)
{
	int message_len = strlen(message) + 1;
	int packet_len = 2 + 2 + 2 + message_len;

	WFIFOHEAD(fd, packet_len);
	WFIFOW(fd, 0) = SC_GEPARD_INFO;
	WFIFOW(fd, 2) = packet_len;
	WFIFOW(fd, 4) = info_type;
	safestrncpy((char*)WFIFOP(fd, 6), message, message_len);
	WFIFOSET(fd, packet_len);
}