#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ws2tcpip.h>
#include "windivert.h"
#include <windows.h>
#include <iostream>
using namespace std;
#define MAXBUF  0xFFFF
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

UINT32 targetip;
UINT32 ProxyIP;

int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	UINT payload_len;
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
	UINT32 old_ip = 0;
	UINT16 old_port = 0;
	// Main loop:
	inet_pton(AF_INET, "10.100.111.117", &ProxyIP);
	inet_pton(AF_INET, "121.131.52.53", &targetip);
	while (TRUE)
	{
		int count = 0;
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))
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



			if (ip_header->DstAddr == targetip &&  ntohs(tcp_header->DstPort) == 80) //접속하려는 port     
			{
				printf("1. SYN : %d ACK: %d   PSH : %d\n", tcp_header->Syn, tcp_header->Ack, tcp_header->Psh);
				for (int i = 0; i < packet_len; i++)
				{
					printf("%02x ", packet[i]);
					if (i != 0 && i % 15 == 0)
						printf("\n");

				}


				if (tcp_header->Psh == 1 && tcp_header->Ack == 1)
				{
					//outbound
					
					ip_header->DstAddr = ProxyIP;
					tcp_header->DstPort = htons(8080);
					printf("syn, psh\n");
					printf("src_ip : %u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
					printf("dst_ip : %u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
					printf("src port : %d\n", ntohs(tcp_header->SrcPort));
					printf("dst port : %d\n", ntohs(tcp_header->DstPort));
					printf("outbound\n");
					WinDivertHelperCalcChecksums(packet, packet_len, 0);
				//printf("old_port : %d\n", ntohs(old_port));
					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
						printf("error : don't send");
					count++;


					//http ok 사인을 보내줘야됨.

				}
				if(count != 1)
				{
					//inbound
					old_ip = ip_header->DstAddr; //이게 접속하려는 IP
					old_port = tcp_header->DstPort; // 접속하려는 port
					ip_header->DstAddr = ProxyIP;
					tcp_header->DstPort = htons(8080);
					WinDivertHelperCalcChecksums(packet, packet_len, 0);
					printf("old_port : %d\n", ntohs(old_port));
					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
						printf("error : don't send");
				}
				if (count == 1)
				{
					count = 0;
					continue;
				}

			}
			else if (ntohs(tcp_header->SrcPort) == 8080)
			{
				printf("2(8080). SYN : %d ACK: %d   PSH : %d\n", tcp_header->Syn, tcp_header->Ack, tcp_header->Psh);
				printf("src port : %d", ntohs(tcp_header->SrcPort));
				printf("dst port : %d", ntohs(tcp_header->DstPort));
				for (int i = 0; i < packet_len; i++)
				{
					printf("%02x ", packet[i]);
					if (i != 0 && i % 15 == 0)
						printf("\n");
				}
				/*
				if (tcp_header->Psh == 1 && tcp_header->Ack == 1)
				{
					//inbound

					ip_header->SrcAddr = targetip;
					tcp_header->SrcPort = old_port;
					printf("syn, psh\n");
					printf("src_ip : %u.%u.%u.%u\n", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
					printf("dst_ip : %u.%u.%u.%u\n", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
					printf("src port : %d\n", ntohs(tcp_header->SrcPort));
					printf("dst port : %d\n", ntohs(tcp_header->DstPort));
					printf("inbound\n");
					WinDivertHelperCalcChecksums(packet, packet_len, 0);
					recv_addr.Direction = WINDIVERT_DIRECTION_INBOUND;
					printf("old_port : %d\n", ntohs(old_port));
					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
						printf("error : don't send");
				}
				*/
				
					ip_header->SrcAddr = old_ip; //target ip
					tcp_header->SrcPort = old_port; // target port 80
					WinDivertHelperCalcChecksums(packet, packet_len, 0);
					recv_addr.Direction = WINDIVERT_DIRECTION_INBOUND;
					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
						printf("error : don't send");
				
				

			}
		}

		putchar('\n');
	}
}


