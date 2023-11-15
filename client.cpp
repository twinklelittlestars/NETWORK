#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace std;
const int MaxMsgSize = 15000;// 最大文件大小
const int MaxPacketSize = 1500;// 最大发送数据包
const int MaxWaitTimeOver = 3000;// 最大等待时间
const int MaxSendTimeOver = 1500;

const int TranPort = 10000;
const int clientPort = 20000;

//UDP协议中连接服务器的相关实现
class ReliableUDPClient {
public:
    ReliableUDPClient();
    void connectToServer(const std::string& serverIp, int serverPort);// 连接到服务器
    void sendFile(const std::string& filePath);// 发送文件
    void closeConnection();// 关闭连接
    void initializeSocket();     // 初始化套接字

private:
    SOCKET clientSocket;//客户端套接字
    SOCKADDR_IN serverAddress;
    unsigned int sequenceNumber;

    void performHandshake();     // 三次握手
    void performClosure();       // 四次挥手
    void sendPacket(const Packet& packet);// 发送数据包
    bool waitForAck(Packet& packet);// 等待确认
    void logPacket(const Packet& packet);// 日志记录函数
};

//数据包结构体
struct Packet {
    unsigned int srcIP, destIP;      // 源和目的IP地址
    unsigned short srcPort, destPort;// 源和目的端口号
    unsigned int seqNum;             // 序列号
    unsigned int ackNum;             // 确认号
    unsigned int dataSize;           // 数据大小
    unsigned short flags;            // 标志位（如SYN, ACK等）
    unsigned short checksum;         // 校验和
    char data[MaxPacketSize];           // 数据部分

    Packet();
    void computeChecksum();// 计算校验和
    bool verifyChecksum() const;// 验证校验和
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



//初始化WSAStartup
ReliableUDPClient::ReliableUDPClient() 
    : clientSocket(INVALID_SOCKET), sequenceNumber(0) {
    // 初始化 Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		cout << "WSAStartup failed！\n" << endl;
		exit(EXIT_FAILURE);
	}
	cout << "WSAStartup success!\n" << endl;

}
//初始化套接字
void ReliableUDPClient::initializeSocket() {
    // 创建 UDP 套接字,套接字的操作不会等待操作完成就返回
    clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cout << "Failed to create socket, error: " << WSAGetLastError() << endl;
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 设置套接字的非阻塞模式,
    unsigned long mode = 1;  // 0阻塞模式, 1非阻塞模式
    if (ioctlsocket(clientSocket, FIONBIO, &mode) != 0) {
        cout << "Failed to set socket to non-blocking mode, error: " << WSAGetLastError() << endl;
        closesocket(clientSocket);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    // 初始化 serverAddress 结构
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET; // 设置地址族为IPv4
    //serverAddress.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

}

void ReliableUDPClient::connectToServer(const std::string& serverIp, int serverPort) {
    //设置服务器地址
    serverAddress.sin_addr.S_un.S_addr = inet_addr(serverIp.c_str());
    serverAddress.sin_port = htons(static_cast<u_short>(serverPort));

    //开始三次握手
    performHandshake();
}

void ReliableUDPClient::performHandshake() {
    Packet synPacket,synackPacket,ackPacket;
    clock_t startTime ;
    bool synackReceived = false;

    // 第一次握手: 发送SYN包
    /*sequenceNumber++ 表示每次发送数据包时，
    序列号都会递增，htonl 函数（Host TO Network Long）
    用于将序列号从主机字节顺序转换为网络字节顺序
    synPacket.seqNum = htonl(sequenceNumber++);*/
    synPacket.flags = htons(0x1); //0x1 代表SYN标志位，因为发送SYN包，所以将其置位
    synPacket.computeChecksum();
    sendPacket(synPacket);
    cout << "发送SYN包" << endl;

    // 第二次握手: 等待SYN-ACK包
    bool synackReceived = false;
    startTime = clock();
    while (!synackReceived) {
        if (waitForAck(synackPacket)) { // 将synackPacket传递给waitForAck函数
            if (synackPacket.verifyChecksum() && (ntohs(synackPacket.flags) & 0x3) == 0x3) {
                // 收到有效的SYN-ACK包
                synackReceived = true;
                cout << "收到了有效的SYN-ACK包" << endl;
            } else {
                cout << "收到了无效的SYN-ACK包，等待中..." << endl;
            }
        }
        if (clock() - startTime > MaxWaitTimeOver) {
            // 超时，重发SYN包
            sendPacket(synPacket);
            cout << "SYN-ACK包已经超时， 重发中..." << endl;
            startTime = clock();
        }
    }

    // 第三次握手: 发送ACK包
    ackPacket.seqNum = htonl(sequenceNumber++);
    ackPacket.ackNum = htonl(ntohl(synackPacket.seqNum) + 1); // 确认号为接收序列号+1
    ackPacket.flags = htons(0x2); // ACK flag
    ackPacket.computeChecksum();
    sendPacket(ackPacket);
    cout << "发送ACK包， 连接建立！" << endl;
}

//注意sendPacket和waitForAck函数需要封装sendto和recvfrom调用等底层的UDP发送和接收逻辑，并且waitForAck函数应该正确地填充synackPacket。

void ReliableUDPClient::closeConnection()
{
    // 开始四次挥手断开连接
    performClosure();
}

void ReliableUDPClient::performClosure()
{
    Packet finPacket, ackPacket, serverfinPacket, finalackPacket;
    clock_t startTime, tempClock;

    // 第一次挥手：发送FIN包
    finPacket.flags = htons(0x4); // 设置FIN标志
    finPacket.seqNum = htonl(sequenceNumber++);
    finPacket.computeChecksum();
    sendPacket(finPacket);
    cout << "客户端已发送第一次挥手的FIN包" << endl;

    // 第二次挥手：接收ACK包
    startTime = clock();
    while (true) {
        if (waitForAck(ackPacket)) {
            if (ackPacket.verifyChecksum() && (ntohs(ackPacket.flags) & 0x2) == 0x2) {
                cout << "客户端已收到第二次挥手的ACK包" << endl;
                break;
            }
        }
        if (clock() - startTime > MaxWaitTimeOver) {
            cout << "第一次挥手超时，正在重传FIN包" << endl;
            sendPacket(finPacket);
            startTime = clock();
        }
    }

    // 第三次挥手：接收服务器的FIN包
    startTime = clock();
    while (true) {
        if (waitForAck(serverfinPacket)) {
            if (serverfinPacket.verifyChecksum() && (ntohs(serverfinPacket.flags) & 0x4) == 0x4) {
                cout << "客户端已收到第三次挥手的FIN包" << endl;
                break;
            }
        }
        if (clock() - startTime > MaxWaitTimeOver) {
            cout << "等待服务器FIN包超时，继续等待" << endl;
            startTime = clock();
        }
    }

    // 第四次挥手：发送ACK包
    finalackPacket.flags = htons(0x2); // 设置ACK标志
    finalackPacket.ackNum = htonl(ntohl(serverfinPacket.seqNum) + 1); // 确认号为服务器FIN序列号+1
    finalackPacket.computeChecksum();
    sendPacket(finalackPacket);
    cout << "客户端已发送第四次挥手的ACK包" << endl;

    // 等待2MSL时长，确保最后的ACK不丢失
    tempClock = clock();
    cout << "客户端开始2MSL等待..." << endl;
    Packet tmpPacket;

    while (clock() - tempClock < 2 * MaxWaitTimeOver) {
        if (waitForAck(tmpPacket)) {
            if (tmpPacket.verifyChecksum()) {
                cout << "收到迟到的包，回复ACK" << endl;
                sendPacket(finalackPacket);
            }
        }
    }

    cout << "\n客户端连接成功关闭！" << endl;
}

void ReliableUDPClient::sendPacket(const Packet& packet) {
    // 将Packet结构体序列化为字节流
    char buffer[sizeof(Packet)];
    memcpy(buffer, &packet, sizeof(Packet));

    // 通过UDP套接字发送数据
    int sentBytes = sendto(clientSocket, buffer, sizeof(buffer), 0, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    if (sentBytes == SOCKET_ERROR) {
        cerr << "发送数据包出错：" << WSAGetLastError() << endl;
    } else {
        cout << "成功发送数据包！" << endl;
    }
}

bool ReliableUDPClient::waitForAck(Packet& packet) {
    char buffer[sizeof(Packet)];
    int serverAddrLen = sizeof(serverAddress);

    // 非阻塞接收数据，即使没有数据到来，函数也会立即返回
    int receivedBytes = recvfrom(clientSocket, buffer, sizeof(buffer), 0,  (struct sockaddr*)&serverAddress, &serverAddrLen);
    if (receivedBytes > 0) {
        // 成功接收到数据包，反序列化为Packet结构体
        memcpy(&packet, buffer, sizeof(Packet));
        cout << "成功收到数据包！" << endl;
        return true;
    } else if (receivedBytes == 0 || WSAGetLastError() == WSAEWOULDBLOCK) {
        // 没有数据可读
        return false;
    } else {
        // 接收失败
        cerr << "接收数据包出错：" << WSAGetLastError() << endl;
        return false;
    }
}

void ReliableUDPClient::sendFile(const std::string& filePath) {
    // 打开文件
    ifstream fileStream(filePath, ios::binary);
    if (!fileStream) {
        cerr << "无法打开文件: " << filePath << endl;
        return;
    }

    // 读取文件内容
    vector<char> fileData((istreambuf_iterator<char>(fileStream)), istreambuf_iterator<char>());//将文件流转换为vector<char>类型
    fileStream.close();

    // 文件大小超过最大限制
    if (fileData.size() > MaxMsgSize) {
        cerr << "文件太大，无法发送。" << endl;
        return;
    }

    // 获取文件名
    string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);

    // 发送文件名和大小，直到确认
    Packet fileinfoPacket;// 文件信息包
    memset(&fileinfoPacket, 0, sizeof(fileinfoPacket));
    fileinfoPacket.srcPort = htons(clientPort);
    fileinfoPacket.destPort = htons(TranPort);
    fileinfoPacket.seqNum = htonl(sequenceNumber++);
    strncpy(fileinfoPacket.data, fileName.c_str(), min(fileName.size(), static_cast<size_t>(MaxPacketSize)));// 将文件名拷贝到数据部分
    fileinfoPacket.dataSize = htonl(fileData.size());
    fileinfoPacket.computeChecksum();
    sendPacket(fileinfoPacket);

    // 重传逻辑
    clock_t startTime;
    Packet ackPacket;
    int retryCount = 0;
    const int MaxRetryCount = 5;

    while (retryCount < MaxRetryCount) {
        sendPacket(fileinfoPacket);

        startTime = clock();
        while (true) {
            if (waitForAck(ackPacket)) {
                break; // 成功接收到确认
            }
            if (clock() - startTime > MaxSendTimeOver) {
                retryCount++;
                cout << "重试发送文件信息, 尝试次数: " << retryCount << endl;
                break; // 超时，重新发送
            }
        }

        if (retryCount >= MaxRetryCount) {
            cerr << "文件信息发送失败，超出最大重试次数" << endl;
            return;
        }
    }

    // 分块发送文件内容
    for (size_t offset = 0; offset < fileData.size(); offset += MaxPacketSize) {
        retryCount = 0;

        while (retryCount < MaxRetryCount) {
            Packet dataPacket;
            memset(&dataPacket, 0, sizeof(dataPacket));
            dataPacket.srcPort = htons(clientPort);
            dataPacket.destPort = htons(TranPort);
            dataPacket.seqNum = htonl(sequenceNumber++);
            size_t chunkSize = min(fileData.size() - offset, static_cast<size_t>(MaxPacketSize));
            memcpy(dataPacket.data, &fileData[offset], chunkSize);
            dataPacket.dataSize = htonl(chunkSize);
            dataPacket.computeChecksum();
            sendPacket(dataPacket);

            startTime = clock();
            while (true) {
                if (waitForAck(ackPacket)) {
                    break; // 成功接收到确认
                }
                if (clock() - startTime > MaxSendTimeOver) {
                    retryCount++;
                    cout << "重试发送数据块, 尝试次数: " << retryCount << ", 块偏移: " << offset << endl;
                    break; // 超时，重新发送
                }
            }

            if (retryCount >= MaxRetryCount) {
                cerr << "数据块发送失败，序列号: " << sequenceNumber - 1 << endl;
                return;
            }
        }
    }

    cout << "文件发送完成: " << filePath << endl;
}

int main()
{
    // 创建和初始化ReliableUDPClient对象
    ReliableUDPClient client;
    client.initializeSocket(); // 初始化套接字

    string serverIp = "127.0.0.1"; // 设置Router的IP
    int serverPort = TranPort;     // 监听的端口号

    // 连接到服务器
    client.connectToServer(serverIp, serverPort);

    // 主循环
    bool isRunning = true;
    while (isRunning) {
        string command;
        cout << "若要发送文件请输入 'send'，若要断开连接请输入 'over'" << endl;
        cin >> command;

        if (command == "send") {
            // 传输文件
            string filename;
            cout << "请输入文件路径：" << endl;
            cin >> filename;
            client.sendFile(filename);
        } else if (command == "over") {
            // 终止连接
            isRunning = false;
        } else {
            cout << "输入错误，按照要求输入！" << endl;
        }
    }

    // 关闭连接
    client.closeConnection();

    // 清理Winsock资源
    WSACleanup();

    return 0;
}
