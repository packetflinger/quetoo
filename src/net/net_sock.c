/*
 * Copyright(c) 1997-2001 id Software, Inc.
 * Copyright(c) 2002 The Quakeforge Project.
 * Copyright(c) 2006 Quetoo.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <errno.h>

#if defined(_WIN32)
  #define ioctl ioctlsocket

  #include <Objectively/URLSession.h>
#else
  #include <netdb.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <sys/ioctl.h>
  #include <sys/uio.h>
  #include <sys/socket.h>
#endif

#include "net_sock.h"

in_addr_t net_lo;

int32_t Net_GetError(void) {
#if defined(_WIN32)
  return WSAGetLastError();
#else
  return errno;
#endif
}

/**
 * @return A printable error string for the most recent OS-level network error.
 */
const char *Net_GetErrorString(void) {
#if defined(_WIN32)
  static char s[MAX_STRING_CHARS] = { 0 };
  
  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
           NULL, Net_GetError(),
           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
           s, sizeof(s), NULL);
  
  return s;
#else
  return strerror(Net_GetError());
#endif
}

/**
 * @brief Initializes the specified sockaddr_in according to the net_addr_t.
 */
void Net_NetAddrToSockaddr(const net_addr_t *a, struct sockaddr_storage *s) {

  net_sockaddr  *s4 = (net_sockaddr  *)s;
  net_sockaddr6 *s6 = (net_sockaddr6 *)s;

  memset(s, 0, sizeof(*s));

  if (a->type == NA_BROADCAST) {
    s4->sin_family = AF_INET;
    s4->sin_addr.s_addr = INADDR_BROADCAST;
    s4->sin_port = a->port;
  } else if (a->type == NA_DATAGRAM) {
    if (a->v6) {
      s6->sin6_family = AF_INET6;
      s6->sin6_port = a->port;
      s6->sin6_scope_id = a->scope;
      memcpy(&s6->sin6_addr, &a->ip, 16);
    } else {
      s4->sin_family = AF_INET;
      s4->sin_port = a->port;
      memcpy(&s4->sin_addr, &a->ip, 4);
    }
  }
}

/**
 * @return True if the addresses share the same base and port.
 */
bool Net_CompareNetaddr(const net_addr_t *a, const net_addr_t *b) {
  if (a->v6){
    return !memcmp(a->ip.u8, b->ip.u8, 16) && a->port == b->port;
  }
  return a->ip.u32[0] == b->ip.u32[0] && a->port == b->port;
}

/**
 * @return True if the addresses share the same type and base.
 */
bool Net_CompareClientNetaddr(const net_addr_t *a, const net_addr_t *b) {
  if (a->v6) {
    return !memcmp(a->ip.u8, b->ip.u8, 16) && a->type == b->type;
  }
  return a->type == b->type && a->ip.u32[0] == b->ip.u32[0];
}

/**
 * @brief Return a string representation of the base and port
 */
const char *Net_NetaddrToString(const net_addr_t *a) {
  static char s[64];
  char t[INET6_ADDRSTRLEN];

  if (a->v6) {
    inet_ntop(AF_INET6, &a->ip.u8, t, INET6_ADDRSTRLEN);
  } else {
    inet_ntop(AF_INET, &a->ip.u8, t, INET_ADDRSTRLEN);
  }
  g_snprintf(s, sizeof(s), "%s:%i", t, ntohs(a->port));

  return s;
}

/**
 * @brief Returns the IP address of a net_addr_t as a string, without port.
 * @remarks Uses a static buffer; not reentrant.
 */
const char *Net_NetaddrToIpString(const net_addr_t *a) {
  static char s[INET6_ADDRSTRLEN];

  if (a->v6) {
    inet_ntop(AF_INET6, &a->ip.u8, s, INET6_ADDRSTRLEN);
  } else {
    inet_ntop(AF_INET, &a->ip.u8, s, INET_ADDRSTRLEN);
  }

  return s;
}

/**
 * @brief getaddrinfo will return multiple entries of mixed address families,
 * find the first entry for a particular family.
 */
static struct addrinfo Net_SearchAddrinfo(struct addrinfo *a, int family) {
  while (a) {
    if (a->ai_family == family) {
      return a;
    }
    a = a->ai_next;
  }

  return NULL;
}

/**
 * @brief Resolve internet hostnames to sockaddr. Examples:
 *
 * localhost
 * idnewt
 * idnewt:28000
 * 192.246.40.70
 * 192.246.40.70:28000
 * justaimdown.example.com
 * [2001:db8::b00b:f4ce]:1998
 */
bool Net_StringToSockaddr(const char *s, struct sockaddr_storage *saddr) {

  bool preferv6 = true; // make this a cvar once everything works
  memset(saddr, 0, sizeof(*saddr));

  char *node = g_strdup(s);

  char *service = strchr(node, ':');
  if (service) {
    *service++ = '\0';
  }

  const struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_DGRAM,
    .ai_flags = AI_ADDRCONFIG
  };

  struct addrinfo *info, *found;
  if (getaddrinfo(node, service, &hints, &info) == 0) {
    found = Net_SearchAddrinfo(info, preferv6 ? AF_INET6 : AF_INET);
    if (!found) {
        found = info;
    }
    memcpy(saddr, found->ai_addr, sizeof(*saddr));
    freeaddrinfo(info);
  }

  g_free(node);

  return ((net_sockaddr *)saddr)->sin_addr.s_addr != 0;
}

/**
 * @brief Parses the hostname and port into the specified net_addr_t.
 */
bool Net_StringToNetaddr(const char *s, net_addr_t *a) {

  struct sockaddr_storage saddr;

  if (!Net_StringToSockaddr(s, &saddr)) {
    return false;
  }

  memset(a, 0, sizeof(net_addr_t));

  const struct sockaddr_in  *s4 = (const struct sockaddr_in  *)s;
  const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)s;

  switch (saddr.ss_family) {
  case AF_INET:
    memcpy(a->ip, &s4->sin_addr, 4);
    a->port = s4->sin_port;
    a->type = NA_DATAGRAM;
    break;

  case AF_INET6:
    if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
      a->v6 = false;
      memcpy(&a->ip, &s6->sin6_addr.s6_addr[12], 4);
    } else {
      a->v6 = true;
      memcpy(&a->ip, &s6->sin6_addr, 16);
      a->scope = s6->sin6_scope_id;
    }
    a->port = s6->sin6_port;
    a->type = NA_DATAGRAM;
    break;
  }

  if (g_strcmp0(s, "localhost") == 0) {
    a->port = 0;
    a->type = NA_LOOP;
  }

  return true;
}

/**
 * @brief Creates and binds a new network socket for the specified protocol.
 */
int32_t Net_Socket(net_addr_type_t type, const char *iface, in_port_t port, int v6) {
  int32_t sock, i = 1;

  switch (type) {
    case NA_BROADCAST:
    case NA_DATAGRAM:
      if ((sock = socket(v6 ? PF_INET6 : PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        Com_Error(ERROR_DROP, "socket: %s\n", Net_GetErrorString());
      }

      if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const void *) &i, sizeof(i)) == -1) {
        Com_Error(ERROR_DROP, "setsockopt: %s\n", Net_GetErrorString());
      }

      Net_SetNonBlocking(sock, true);
      break;

    case NA_STREAM:
      if ((sock = socket(v6 ? PF_INET6 : PF_INET, SOCK_STREAM, 0)) == -1) {
        Com_Error(ERROR_DROP, "socket: %s\n", Net_GetErrorString());
      }

      if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const void *) &i, sizeof(i)) == -1) {
        Com_Error(ERROR_DROP, "setsockopt: %s\n", Net_GetErrorString());
      }
      break;

    default:
      Com_Error(ERROR_DROP, "Invalid socket type: %d\n", type);
  }

  net_sockaddr addr;
  memset(&addr, 0, sizeof(addr));

  if (iface) {
    Net_StringToSockaddr(iface, &addr);
  } else {
    addr.sin_family = v6 ? AF_INET6 : AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
  }

  addr.sin_port = htons(port);

  if (bind(sock, (void *) &addr, sizeof(addr)) == -1) {
    Com_Error(ERROR_DROP, "bind: %s\n", Net_GetErrorString());
  }

  return sock;
}

/**
 * @brief Creates a non-blocking TCP listen socket with SO_REUSEADDR.
 * @return The socket descriptor, or -1 on failure.
 */
int32_t Net_SocketListen(const char *iface, in_port_t port, int32_t backlog, bool v6) {
  int32_t opt = 1;

  const int32_t sock = socket(v6 ? PF_INET6 : PF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    Com_Warn("socket: %s\n", Net_GetErrorString());
    return -1;
  }

  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &opt, sizeof(opt));
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const void *) &opt, sizeof(opt));

  net_sockaddr addr;
  memset(&addr, 0, sizeof(addr));

  if (iface) {
    Net_StringToSockaddr(iface, &addr);
  } else {
    addr.sin_family = v6 ? AF_INET6 : AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
  }

  addr.sin_port = htons(port);

  if (bind(sock, (void *) &addr, sizeof(addr)) == -1) {
    Com_Warn("bind: %s\n", Net_GetErrorString());
    Net_CloseSocket(sock);
    return -1;
  }

  Net_SetNonBlocking(sock, true);

  if (listen(sock, backlog) == -1) {
    Com_Warn("listen: %s\n", Net_GetErrorString());
    Net_CloseSocket(sock);
    return -1;
  }

  return sock;
}

/**
 * @brief Accept a connection on a listening socket.
 * @param from If non-NULL, receives the remote address.
 * @return The accepted socket descriptor, or -1 if none pending.
 */
int32_t Net_Accept(int32_t sock, net_addr_t *from) {
  net_sockaddr addr;
  socklen_t addr_len = sizeof(addr);

  const int32_t client = accept(sock, (struct sockaddr *) &addr, &addr_len);
  if (client == -1) {
    return -1;
  }

  Net_SetNonBlocking(client, true);

  if (from) {
    from->type = NA_STREAM;
    from->addr = addr.sin_addr.s_addr;
    from->port = addr.sin_port;
  }

  return client;
}

/**
 * @brief Send data on a connected socket.
 * @return Bytes sent, or -1 on error.
 */
ssize_t Net_Send(int32_t sock, const void *data, size_t len) {
  return send(sock, data, len, 0);
}

/**
 * @brief Receive data from a connected socket.
 * @return Bytes received, 0 on close, or -1 on error.
 */
ssize_t Net_Recv(int32_t sock, void *data, size_t len) {
  return recv(sock, data, len, 0);
}

/**
 * @brief Make the specified socket non-blocking.
 */
void Net_SetNonBlocking(int32_t sock, bool non_blocking) {
  int32_t i = non_blocking;

  if (ioctl(sock, FIONBIO, (void *) &i) == -1) {
    Com_Error(ERROR_DROP, "ioctl: %s\n", Net_GetErrorString());
  }
}

/**
 * @brief
 */
void Net_CloseSocket(int32_t sock) {
#if defined(_WIN32)
  closesocket(sock);
#else
  close(sock);
#endif
}

/**
 * @brief
 */
void Net_Init(void) {

#if defined(_WIN32)
  WORD v;
  WSADATA d;

  v = MAKEWORD(2, 2);
  WSAStartup(v, &d);
#endif

  net_lo = inet_addr("127.0.0.1");
}

/**
 * @brief
 */
void Net_Shutdown(void) {

#if defined(_WIN32)
  #if defined(_MSC_VER)
  // HACK: With MSVC runtime, exit() terminates all threads before dispatching
  // atexit() hooks, which means that the URLSession's thread is already gone
  // before normal Objectively teardown and destroy operations can get to it.
  // As a workaround, we explicitly cancel the URLSession's worker thread here,
  // from the main thread, well before exit().
  #undef interface // Windows COM headers redefine this, breaking Objectively macros
  URLSession *session = $$(URLSession, sharedInstance);
  $(session, invalidateAndCancel);
  #endif
  WSACleanup();
#endif

}
