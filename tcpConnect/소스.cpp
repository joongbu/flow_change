#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ws2tcpip.h>
#include "windivert.h"
#include <windows.h>
#include <iostream>
#include <thread>
#include <map>
#define MAXBUF  0xFFFF
UINT32 ProxyIP;
struct oldpacket{
	UINT32 old_ip;
	UINT16 old_port;
	
};
bool operator < (const oldpacket &first , const oldpacket &second)
{
	return (first.old_ip < second.old_ip || (first.old_ip == second.old_ip && first.old_port < second.old_port));
}
bool operator == (const oldpacket &first, const oldpacket &second)
{
	return (first.old_ip == second.old_ip && first.old_port == second.old_port);
}
bool operator > (const oldpacket &first, const oldpacket &second)
{
	return (first.old_ip > second.old_ip || (first.old_ip == second.old_ip && first.old_port > second.old_port));
}
std::map<oldpacket,oldpacket> m;
void function(HANDLE h)
{
	oldpacket old_src, old_dst, new_src, new_dst;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	UINT payload_len;
	while (TRUE)
	{
		if (!WinDivertRecv(h, packet, sizeof(packet), &recv_addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);
		if (ip_header == NULL)
		{
			continue;
		}
		if (ip_header != NULL && tcp_header != NULL)
		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			if (ntohs(tcp_header->DstPort) == 80)
			{
				printf("src_ip : %u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
				printf("dst_ip : %u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				printf("src port : %d\n", ntohs(tcp_header->SrcPort));
				printf("dst port : %d\n", ntohs(tcp_header->DstPort));
				old_src.old_ip = ip_header->SrcAddr;
				old_src.old_port = tcp_header->SrcPort;
				old_dst.old_ip = ip_header->DstAddr;
				old_dst.old_port = tcp_header->DstPort;
				m[old_src] = old_dst;
				ip_header->DstAddr = ProxyIP;
				tcp_header->DstPort = htons(8080);
				WinDivertHelperCalcChecksums(packet, packet_len, 0);
				//recv_addr.Direction = WINDIVERT_DIRECTION_INBOUND;
				if (!WinDivertSend(h, packet, packet_len, &recv_addr, NULL))
					printf("error : don't send");
			}
			else if (ntohs(tcp_header->SrcPort) == 8080)
			{
				new_dst.old_ip = ip_header->DstAddr;//10.100.111.117 (local)
				new_dst.old_port = tcp_header->DstPort; // src port
				new_src = m[new_dst];
				if ((new_src.old_ip == old_dst.old_ip) && (new_src.old_port == old_dst.old_port))
				{
				ip_header->SrcAddr = new_src.old_ip;
				tcp_header->SrcPort = new_src.old_port;
				printf("2\n");
				printf("src_ip : %u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
				printf("dst_ip : %u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				printf("src port : %d\n", ntohs(tcp_header->SrcPort));
				printf("dst port : %d\n", ntohs(tcp_header->DstPort));
				WinDivertHelperCalcChecksums(packet, packet_len, 0);
				//recv_addr.Direction = WINDIVERT_DIRECTION_INBOUND;
				if (!WinDivertSend(h, packet, packet_len, &recv_addr, NULL))
					printf("error : don't send");
				printf("send!!\n");
				}
			}
		}
		else
		{ 
			WinDivertHelperCalcChecksums(packet, packet_len, 0);
			//recv_addr.Direction = WINDIVERT_DIRECTION_INBOUND;
			if (!WinDivertSend(h, packet, packet_len, &recv_addr, NULL))
				printf("error : don't send");
		}
	}
}
int __cdecl main(int argc, char **argv)
{

	HANDLE handle;
	INT16 priority = 0;
	// Check arguments.
	switch (argc)
	{
	case 3:
		inet_pton(AF_INET, argv[2], &ProxyIP);
		break;
	case 4: 
		priority = (INT16)atoi(argv[3]);
		break;
	default:
		fprintf(stderr, "usage: %s windivert-filter [ProxyIP] [priority]\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}
	
	handle = WinDivertOpen(argv[1], WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	std::thread thread(function, handle);
	thread.join();
}