#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Ws2tcpip.h>
#include "windivert.h"
#define MAXBUF  0xFFFF
typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;
//dst_port 가 web port에 속하는 경우 해당 packet을 dst_ip를 proxy_ip로 변경
char *src_ip, *dst_ip;
char *src_port, *dst_port;
int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
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
	// Main loop:
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		// Print info about the matching packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);
		if (ip_header == NULL)
		{
			continue;
		}
		// Dump packet info: 
		if (ip_header != NULL)
		{
			//UINT32 Ip;
			//inet_pton(AF_INET, victim, &Ip);
			//inet_pton(AF_INET,attack,&ip_header->DstAddr); //changing IP
			//ip_header->Checksum = WinDivertHelperCalcChecksums(packet, packet_len, 0);
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			//printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u \n",
				//src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				//dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			//if (!WinDivertSend(handle, packet, packet_len, &send_addr, NULL))
			//	printf("error : don't send");
			if (tcp_header != NULL)
			{
				UINT16 old_port;
				UINT32 old_ip;
				//printf("input port\n");
				//printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u \n",
				//src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				//dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				//printf("source Port : %d\n", ntohs(tcp_header->SrcPort));
				//printf("destination port : %d\n", ntohs(tcp_header->DstPort));
				//printf("source Port : %d\n", ntohs(tcp_header->SrcPort));
				//printf("destination port : %d\n", ntohs(tcp_header->DstPort));
				//debug
				
				
				
				if (ntohs(tcp_header->DstPort) == 1234)
				{
					old_ip = ip_header->DstAddr;//기존 IP 가지고 있기
					inet_pton(AF_INET, "127.0.0.1", &ip_header->DstAddr);
					old_port = tcp_header->DstPort;//기존 port 가지고 있기
					tcp_header->DstPort = htons(8080);
					tcp_header->Checksum = WinDivertHelperCalcChecksums(packet, packet_len, 0);//해당 하는 proxy port 설정

					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
						printf("error : don't send\n");//보내지지가않는다.

					printf("변경 port\n");
					printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u \n", src_addr[0], src_addr[1], src_addr[2], src_addr[3],
						dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
					printf("source Port : %d\n", ntohs(tcp_header->SrcPort));
					printf("destination port : %d\n", ntohs(tcp_header->DstPort));

					for (int i = 0; i < packet_len; i++)
					{
						if (i % 16 == 0)
							printf("\n");
						printf("%x ", packet[i]);
					}
					if (ntohs(tcp_header->SrcPort) == 8080)//proxy로 부터 패킷이 수신되면(해당포트로 조건? 아니면 IP?)
					{
						ip_header->SrcAddr = old_ip;
						tcp_header->SrcPort = old_port;
						tcp_header->Checksum = WinDivertHelperCalcChecksums(packet, packet_len, 0);
						if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
							printf("error : don't send");
					}


				}
				/*
				if(tcp_header->Syn)
				{

					if((tcp_header->Ack && tcp_header->Syn))
					{
						if(tcp_header->Ack)
						{

						}
					}
				}
				*/
			}

			putchar('\n');
		}
	}
}


