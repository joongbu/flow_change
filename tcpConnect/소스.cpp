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
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;
UINT32 ProxyIP;
struct oldpacket{
	UINT32 old_ip;
	UINT16 old_port;
} ;
UINT32 old_ip;
UINT16 old_port;
std::map<int,oldpacket> m;

bool check = false;
void function(HANDLE h)
{
	oldpacket old;
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
			

				printf("syn, psh\n");
				printf("src_ip : %u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
				printf("dst_ip : %u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				printf("src port : %d\n", ntohs(tcp_header->SrcPort));
				printf("dst port : %d\n", ntohs(tcp_header->DstPort));
				old_ip = ip_header->DstAddr;
				ip_header->DstAddr = ProxyIP;
				old_port = tcp_header->SrcPort;
				tcp_header->DstPort = htons(8080);

				WinDivertHelperCalcChecksums(packet, packet_len, 0);
				if (!WinDivertSend(h, packet, packet_len, &recv_addr, NULL))
					printf("error : don't send");
			}
			else if (ntohs(tcp_header->SrcPort) == 8080)
			{
				printf("syn, psh\n");
				printf("src_ip : %u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
				printf("dst_ip : %u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				printf("src port : %d\n", ntohs(tcp_header->SrcPort));
				printf("dst port : %d\n", ntohs(tcp_header->DstPort));
				ip_header->SrcAddr = old_ip;
				tcp_header->SrcPort = htons(80);
				WinDivertHelperCalcChecksums(packet, packet_len, 0);
				if (!WinDivertSend(h, packet, packet_len, &recv_addr, NULL))
					printf("error : don't send");
				printf("send!!\n");

			}


		}
		else
			if (!WinDivertSend(h, packet, packet_len, &recv_addr, NULL))
				printf("error : don't send");
		if (check)
			break;

	}

}

int __cdecl main(int argc, char **argv)
{

	HANDLE handle;
	INT16 priority = 0;
	// Check arguments.
	switch (argc)
	{
	case 2:
		break;
	case 3:
		priority = (INT16)atoi(argv[2]);
		break;
	default:
		fprintf(stderr, "usage: %s windivert-filter [priority]\n",
			argv[0]);
		fprintf(stderr, "examples:\n");
		fprintf(stderr, "\t%s true\n", argv[0]);
		fprintf(stderr, "\t%s \"outbound and tcp.DstPort == 80\" 1000\n",
			argv[0]);
		fprintf(stderr, "\t%s \"inbound and tcp.Syn\" -4000\n", argv[0]);
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
	// Main loop:
	inet_pton(AF_INET, "10.100.111.121", &ProxyIP);


	std::thread thread(function, handle);
	thread.join();

}