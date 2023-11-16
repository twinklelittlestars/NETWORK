#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include <time.h>
#include <vector>
#pragma comment (lib, "ws2_32.lib")
using namespace std;

const int MaxMsgSize = 15000;// 最大文件大小
const int MaxPacketSize = 1500;// 最大发送数据包
const int MaxWaitTimeOver = 3000;// 最大等待时间
const int MaxSendTimeOver = 1500;

const int TranPort = 10000;
const int serverPort = 30000;

// 数据包结构
struct Packet {
    unsigned int srcIP, destIP;      // 源和目的IP地址
    unsigned short srcPort, destPort;// 源和目的端口号
    unsigned int seqNum;             // 序列号
    unsigned int ackNum;             // 确认号
    unsigned int dataSize;           // 数据大小
    unsigned short flags;            // 标志位（如SYN, ACK等）
    unsigned short checksum;         // 校验和
    char data[MaxMsgSize];           // 数据部分

    Packet();
    void computeChecksum();    // 计算校验和
    bool verifyChecksum() const;    // 验证校验和
};
Packet::Packet() 
    : srcIP(0), destIP(0), srcPort(0), destPort(0), 
    seqNum(0), ackNum(0), dataSize(0), flags(0), checksum(0) {
    memset(data, 0, MaxPacketSize);// 初始化数据部分
}
//计算校验和
void Packet::computeChecksum() {
    checksum = 0;
    unsigned long sum = 0;
    const unsigned short* ptr = reinterpret_cast<const unsigned short*>(this);// 将数据包转换为unsigned short类型

    for (size_t i = 0; i < sizeof(Packet) / 2; ++i) {//遍历数据包的所有16位段
        sum += *ptr++;//计算总和
        //处理溢出
        if (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    checksum = static_cast<unsigned short>(~sum);//取反作为校验和
}

//验证校验和
bool Packet::verifyChecksum() const {
    unsigned long sum = 0;
    const unsigned short* ptr = reinterpret_cast<const unsigned short*>(this);

    for (size_t i = 0; i < sizeof(Packet) / 2; ++i) {
        sum += *ptr++;
        if (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    return (sum == 0xFFFF);
}
//UDP协议中连接客户端的相关实现
class ReliableUDPServer {
public:
    ReliableUDPServer();
    void bindToPort(const std::string& ipAddress, int port);// 绑定到特定端口
    void listenForClient();    // 等待客户端连接
    void receiveFile();    // 接收文件
    void sendDuplicateAck(const Packet& packet);// 发送重复确认
    void writeFile(const string& fileName, const vector<char>& fileBuffer);// 写入文件
    void closeConnection();    // 关闭连接
    void initializeSocket();// 初始化套接字

private:
    SOCKET serverSocket;             
    SOCKADDR_IN serverAddress;       // 服务器地址
    SOCKADDR_IN clientAddress;       // 客户端地址
    unsigned int sequenceNumber; 

    void performHandshake(Packet& packet);     // 三次握手
    void performClosure();       // 四次挥手
    bool receivePacket(Packet& packet);// 接收数据包
    void sendAck(const Packet& packet);// 发送确认
    void logPacket(const Packet& packet);// 日志记录函数
};



//初始化WSAStartup
ReliableUDPServer::ReliableUDPServer() 
    : serverSocket(INVALID_SOCKET), sequenceNumber(0) {
    // 初始化 Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		cout << "WSAStartup failed！\n" << endl;
		exit(EXIT_FAILURE);
	}
	cout << "WSAStartup success!\n" << endl;
    // 初始化 clientAddress
    memset(&clientAddress, 0, sizeof(clientAddress));
    clientAddress.sin_family = AF_INET;

    initializeSocket();
}
//初始化套接字
void ReliableUDPServer::initializeSocket() {
    // 创建 UDP 套接字,套接字的操作不会等待操作完成就返回
    serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cout << "Failed to create socket, error: " << WSAGetLastError() << endl;
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 设置套接字的非阻塞模式,
    unsigned long mode = 1;  // 0阻塞模式, 1非阻塞模式
    if (ioctlsocket(serverSocket, FIONBIO, &mode) != 0) {
        cout << "Failed to set socket to non-blocking mode, error: " << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
}

// 初始化服务器套接字并绑定到端口
void ReliableUDPServer::bindToPort(const std::string& ipAddress, int port) {
    // 初始化 serverAddress 结构
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(ipAddress.c_str());  // 绑定到特定的 IP 地址
    serverAddress.sin_port = htons(static_cast<u_short>(port));

    // 绑定服务器套接字到指定端口
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cout << "Bind failed with error: " << WSAGetLastError() << endl;
        closesocket(serverSocket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    cout << "Server successfully bound to port " << port << endl;
}

//要注意clientAddress 可以在后续的客户端连接处理中被用来保存客户端的地址信息

//接收数据包
bool ReliableUDPServer::receivePacket(Packet& packet) {
    char buffer[sizeof(Packet)];
    int clientAddrLen = sizeof(clientAddress);

    int receivedBytes = recvfrom(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, &clientAddrLen);
    if (receivedBytes > 0) {
        memcpy(&packet, buffer, sizeof(Packet));
        cout << "Packet received successfully!" << endl;
        return true;
    } else if (receivedBytes == 0 || WSAGetLastError() == WSAEWOULDBLOCK) {
        return false;
    } else {
        cout << "Error receiving packet: " << WSAGetLastError() << endl;
        return false;
    }
}

//发送确认
void ReliableUDPServer::sendAck(const Packet& packet) {
    char buffer[sizeof(Packet)];
    memcpy(buffer, &packet, sizeof(Packet));

    int sentBytes = sendto(serverSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&clientAddress, sizeof(clientAddress));
    if (sentBytes == SOCKET_ERROR) {
        cout << "Error sending packet: " << WSAGetLastError() << endl;
    } else {
        cout << "Packet sent successfully!" << endl;
    }
}

// 标志位定义如下
const unsigned short SYN_FLAG = 0x1;
const unsigned short ACK_FLAG = 0x2;
const unsigned short SYN_ACK_FLAG = SYN_FLAG | ACK_FLAG;
void ReliableUDPServer::listenForClient()
{
    cout << "Waiting for client connection..." << endl;
    Packet synPacket;

    while (true) {
        if (receivePacket(synPacket)) {
            // 检查是否是 SYN 包
            if ((ntohs(synPacket.flags) & SYN_FLAG) == SYN_FLAG) {
                cout << "SYN packet received from client, sequence number: " << ntohl(synPacket.seqNum) << endl;
                performHandshake(synPacket);
                break;
            }
        }
    }
}

void ReliableUDPServer::performHandshake(Packet& synPacket) {
    // 首先验证收到的 SYN 包的校验和
    if (!synPacket.verifyChecksum()) {
        cout << "Checksum error in received SYN packet" << endl;
        return; // 校验和错误，终止握手过程
    }

    Packet synAckPacket, ackPacket;
    clock_t startTime;

    // 发送 SYN-ACK 包
    synAckPacket.flags = htons(SYN_ACK_FLAG);
    synAckPacket.ackNum = htonl(ntohl(synPacket.seqNum) + 1);
    synAckPacket.seqNum = htonl(sequenceNumber++);
    synAckPacket.computeChecksum();
    sendAck(synAckPacket);
    cout << "SYN-ACK packet sent" << endl;

    // 等待 ACK 包
    bool ackReceived = false;
    startTime = clock();
    while (!ackReceived) {
        if (receivePacket(ackPacket)) {
            if ((ntohs(ackPacket.flags) & ACK_FLAG) == ACK_FLAG && ackPacket.verifyChecksum()) {
                cout << "ACK packet received, connection established" << endl;
                ackReceived = true;
            }
        }
        if (clock() - startTime > MaxWaitTimeOver) {
            // 超时重发 SYN-ACK 包
            sendAck(synAckPacket);
            cout << "SYN-ACK packet timed out, resending..." << endl;
            startTime = clock();
        }
    }
}

const unsigned short FIN_FLAG = 0x4; // FIN标志位
void ReliableUDPServer::closeConnection()
{
    performClosure();
}

void ReliableUDPServer::performClosure()
{
    Packet finPacket, ackPacket;
    clock_t startTime;

    // 第一步: 等待客户端的FIN包
    bool finReceived = false;
    while (!finReceived) {
        if (receivePacket(finPacket)) {
            if ((ntohs(finPacket.flags) & FIN_FLAG) == FIN_FLAG && finPacket.verifyChecksum()) {
                cout << "FIN packet received, sequence number: " << ntohl(finPacket.seqNum) << endl;
                finReceived = true;
            }else {
                cout << "Invalid FIN packet or checksum error received" << endl;
            }
        }
    }

    // 第二步: 发送ACK包
    ackPacket.flags = htons(ACK_FLAG);
    ackPacket.ackNum = htonl(ntohl(finPacket.seqNum) + 1);
    ackPacket.seqNum = htonl(sequenceNumber++);
    ackPacket.computeChecksum();
    sendAck(ackPacket);
    cout << "ACK packet sent" << endl;

    // 第三步: 发送FIN包
    finPacket.flags = htons(FIN_FLAG);
    finPacket.seqNum = htonl(sequenceNumber++);
    finPacket.computeChecksum();
    sendAck(finPacket);
    cout << "FIN packet sent" << endl;

    // 第四步: 等待客户端的ACK包
    bool ackReceived = false;
    startTime = clock();
    while (!ackReceived) {
        if (receivePacket(ackPacket)) {
            if ((ntohs(ackPacket.flags) & ACK_FLAG) == ACK_FLAG && ackPacket.verifyChecksum()) {
                cout << "ACK packet received, connection closed" << endl;
                ackReceived = true;
            }else {
                cout << "Invalid ACK packet or checksum error received" << endl;
            }
        }
        if (clock() - startTime > MaxWaitTimeOver) {
            // 超时重发FIN包
            sendAck(finPacket);
            cout << "FIN packet timed out, resending..." << endl;
            startTime = clock();
        }
    }
}

void ReliableUDPServer::receiveFile() {
    cout << "Starting file reception..." << endl;

    // 文件名和大小
    string fileName;
    size_t fileSize = 0;

    // 第一步：接收文件名和文件大小
    Packet namePacket;
    bool nameReceived = false;
    while (!nameReceived) {
        if (receivePacket(namePacket)) {
        if (namePacket.verifyChecksum() && ntohl(namePacket.seqNum) == sequenceNumber) {
            // 解析文件信息
                // 解析文件信息
                fileName.assign(namePacket.data, strnlen(namePacket.data, sizeof(namePacket.data)));
                fileSize = ntohl(namePacket.dataSize);
                cout << "File name received: " << fileName << ", size: " << fileSize << endl;

                // 确认文件信息包
                Packet ackPacket;
                ackPacket.flags = htons(ACK_FLAG);
                ackPacket.ackNum = htonl(ntohl(namePacket.seqNum) + 1);
                ackPacket.seqNum = htonl(sequenceNumber++);
                ackPacket.computeChecksum();
                sendAck(ackPacket);
                cout << "ACK packet sent, sequence number: " << ntohl(namePacket.seqNum) << endl;

                nameReceived = true;
            } else {
                // 发送重复包确认
                sendDuplicateAck(namePacket);
            }
        }
    }

    // 第二步：分批接收文件数据
    size_t receivedBytes = 0;
    ofstream outputFile(fileName, ios::binary);
    if (!outputFile.is_open()) {
        cout << "Unable to create file: " << fileName << endl;
        return;
    }

    while (receivedBytes < fileSize) {
        Packet dataPacket;
        if (receivePacket(dataPacket)) {
            if (dataPacket.verifyChecksum() && ntohl(dataPacket.seqNum) == sequenceNumber) {
                // 正确顺序的数据包
                size_t chunkSize = ntohl(dataPacket.dataSize);
                outputFile.write(dataPacket.data, chunkSize);
                receivedBytes += chunkSize;

                // 确认数据包
                Packet ackPacket;
                ackPacket.flags = htons(ACK_FLAG);
                ackPacket.ackNum = htonl(ntohl(dataPacket.seqNum) + 1);
                ackPacket.seqNum = htonl(sequenceNumber++);
                ackPacket.computeChecksum();
                sendAck(ackPacket);
                cout << "ACK packet sent, sequence number: " << ntohl(dataPacket.seqNum) << endl;
            } else {
                // 重复包或校验和错误
                sendDuplicateAck(dataPacket);
            }
        }
    }

    outputFile.close();
    cout << "File reception completed: " << fileName << endl;
}

void ReliableUDPServer::sendDuplicateAck(const Packet& packet) {
    Packet ackPacket;
    ackPacket.flags = htons(ACK_FLAG);
    ackPacket.ackNum = htonl(ntohl(packet.seqNum) + 1);
    ackPacket.computeChecksum();
    sendAck(ackPacket);
    cout << "Sending duplicate ACK packet, sequence number: " << ntohl(packet.seqNum) << endl;
}

int main()
{
    // 创建服务器实例
    ReliableUDPServer server;

    // 绑定到特定的 IP 地址和端口
    std::string serverIp = "127.0.0.1"; // 特定的 IP 地址
    server.bindToPort(serverIp, serverPort);


    // 等待客户端连接
    cout << "Waiting for client connection..." << endl;
    server.listenForClient();

    // 接收文件
    cout << "Receiving file from client..." << endl;
    server.receiveFile();

    // 关闭连接
    cout << "Closing connection..." << endl;
    server.closeConnection();

    cout << "Server operations completed." << endl;
    return 0;
}