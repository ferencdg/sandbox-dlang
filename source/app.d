module agora.utils.InetUtils;

import agora.utils.Log;

import std.algorithm;
import std.algorithm.searching;
import std.array;
import std.conv;
import std.socket;

import core.stdc.string;

// Linux(Dlang)
// netdb.d
//int   getnameinfo(const(sockaddr)*, socklen_t, char*, socklen_t, char*, socklen_t, int);
// ifaddr.d
//int getifaddrs(ifaddrs** );
//void freeifaddrs(ifaddrs* );

// Linux(Dlang)
    // socket.d
    // struct sockaddr
    // {
    //     sa_family_t sa_family;
    //     byte[14]    sa_data;
    // }
    // socket.d
    // enum
    // {
    //     AF_APPLETALK    = 5,
    //     AF_INET         = 2,
    //     AF_IPX          = 4,
    //     AF_UNIX         = 1,
    //     AF_UNSPEC       = 0,
    //     PF_APPLETALK    = AF_APPLETALK,
    //     PF_IPX          = AF_IPX
    // }
    // in.d:
    // struct sockaddr_in
    // {
    //     sa_family_t sin_family;
    //     in_port_t   sin_port;
    //     in_addr     sin_addr;

    //     /* Pad to size of `struct sockaddr'. */
    //     ubyte[__SOCK_SIZE__ - sa_family_t.sizeof -
    //           in_port_t.sizeof - in_addr.sizeof] __pad;
    // }

    --------------------------------------------------------------------------------

// OsX(C++)
//int   getnameinfo(const struct sockaddr * __restrict, socklen_t, char * __restrict, socklen_t, char * __restrict, socklen_t, int);
//extern int getifaddrs(struct ifaddrs **);
//extern void freeifaddrs(struct ifaddrs *);

//typedef __uint16_t              in_port_t;
// from _sa_family_t.h
//typedef __uint8_t               sa_family_t;

// struct sockaddr_in {
// 	__uint8_t       sin_len;
// 	sa_family_t     sin_family;
// 	in_port_t       sin_port;
// 	struct  in_addr sin_addr;
// 	char            sin_zero[8];
// };

// struct sockaddr_in6 {
// 	__uint8_t       sin6_len;       /* length of this struct(sa_family_t) */
// 	sa_family_t     sin6_family;    /* AF_INET6 (sa_family_t) */
// 	in_port_t       sin6_port;      /* Transport layer port # (in_port_t) */
// 	__uint32_t      sin6_flowinfo;  /* IP6 flow information */
// 	struct in6_addr sin6_addr;      /* IP6 address */
// 	__uint32_t      sin6_scope_id;  /* scope zone index */
// };

mixin AddLogger!();

import core.sys.posix.netinet.in_;
import core.sys.posix.sys.socket;
import core.sys.posix.netdb;

// from ifaddr.h
int getifaddrs(ifaddrs** );
void freeifaddrs(ifaddrs* );


struct InetUtils
{

    import core.sys.linux.ifaddrs;
    import core.sys.posix.netdb;

    public static string[] getAllIPs()
    {
        string[] ips = [];

        ifaddrs *if_address_head_poi;
        ifaddrs *if_address_poi;

        getifaddrs (&if_address_head_poi);
        scope(exit) freeifaddrs(if_address_head_poi);

        for (if_address_poi = if_address_head_poi; if_address_poi; if_address_poi = if_address_poi.ifa_next)
        {
            if (if_address_poi.ifa_addr &&
            (if_address_poi.ifa_addr.sa_family==AF_INET || if_address_poi.ifa_addr.sa_family==AF_INET6))
            {
                const ipv6 = if_address_poi.ifa_addr.sa_family==AF_INET6;
                const sockaddr_len  = ipv6? .sizeof : sockaddr_in.sizeof;

                char[NI_MAXHOST] buffer;
                int name_info_res = getnameinfo(
                                if_address_poi.ifa_addr,
                                sockaddr_len,
                                buffer.ptr,
                                buffer.length,
                                null,
                                0,
                                NI_NUMERICHOST);
                if (name_info_res)
                {
                    log.error("error happened during a call to getnameinfo, name_info_res code:", name_info_res);
                    continue;
                }
                string ip = buffer[0 .. strlen(buffer.ptr)].idup();
                ips ~= ip;
            }
        }

        return ips;
    }



    public static string[] getPublicIPs()
    {
        return filterIPs(ip => !isPrivateIP(ip));
    }

    public static string[] getPrivateIPs()
    {
        return filterIPs(&isPrivateIP);
    }

    private static bool isPrivateIP(string ip)
    {
        bool is_ipv6 = ip.canFind(':');
        if(is_ipv6)
        {
            if(ip == "" || ip == "::" || "::1") // Loopback
                return true;
            ushort[] ip_parts = ip.split("::").map!(ip_part => to!ushort(ip_part,16)).array();
            if(ip_parts.length >= 1)
            {
                if(ip_parts[0] >= to!ushort("fe80",16) && ip_parts[0] <= to!ushort("febf",16)) // Link
                    return true;
                if(ip_parts[0] >= to!ushort("fc00",16) && ip_parts[0] <= to!ushort("fdff",16)) // Private network
                    return true;
                if(ip_parts[0] == to!ushort("100",16)) // Discard prefix
                    return true;
            }
            return false;
        }
        else
        {
            // private and loopback addresses are the followings
            // 10.0.0.0    - 10.255.255.255
            // 172.16.0.0  - 172.31.255.255
            // 192.168.0.0 - 192.168.255.255
            // 169.254.0.0 - 169.254.255.255
            // 127.0.0.0   - 127.255.255.255

            ubyte[] ip_parts = ip.split(".").map!(ip_part => to!ubyte(ip_part)).array();
            return
                (ip_parts[0]==10) ||
                ((ip_parts[0]==172) && (ip_parts[1]>=16 && ip_parts[1]<=31)) ||
                (ip_parts[0]==192 && ip_parts[1]==168) ||
                (ip_parts[0]==169 && ip_parts[1]==254) ||
                (ip_parts[0]==127);
        }
    }

    private static string[] filterIPs(bool function(string ip) filter_func)
    {
        return filter!(ip => filter_func(ip))(getAllIPs()).array();
    }
}


private void main()
{
    import std.stdio;
    writeln(InetUtils.getAllIPs());
}
