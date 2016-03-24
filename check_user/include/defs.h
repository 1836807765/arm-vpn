#ifndef DEFS_H
#define DEFS_H



#define  M_OS           "x86"
#define  M_VERSION      "2.4.0.0"
#define  M_CA_FILE      "/usr/bin/data1"
#define  M_CERT_FILE    "/usr/bin/data2"
#define  M_KEY_FILE     "/usr/bin/data3"
#define  M_CONFIG_FILE  "/etc/data4"

#define CONF_FILE			"/usr/bin/sslvpn.conf"
#define CONF_SERVER_IP		"SERVERIP"
#define CONF_SERVER_PORT	"SERVERPORT"

//定义错误号
#define ERR_OK                      0       // 没有错误
#define ERR_NO_CONFIG              -1       // 配置文件未找到
#define ERR_BAD_CONFIG             -2       // 配置信息错误

#define ERR_CONNECT_REFUSED       -20       // 无法连接到服务器
#define ERR_NO_SERVER             -21       // 安全服务未开启

#define ERR_READ_CERT             -30       // 读取用户证书失败
#define ERR_TF_OPEN               -31       // 打开TF卡失败
#define ERR_TF_LOGIN              -32       // TF卡登陆失败
#define ERR_TF_SN                 -33       // 获取TF卡信息失败
#define ERR_TF_CERT               -34       // 获取证书信息失败

#define ERR_CODEC                 -40       // 内部编码错误
#define ERR_CODEC_J               -41       // 内部编码错误

#define ERR_REQUEST               -50       // 请求失败
#define ERR_VERIFY_FAIL           -51       // 用户认证失败
#define ERR_NET_CONFIG            -52       // 同步网络配置失败

#endif // DEFS_H

