#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
//#include <error.h>
#include "base64/mite_base64.h"
//#include "include/curl/curl.h"
#include <curl/curl.h>
#include "defs.h"
#include "md5/md5_decode.h"
#include "json_handler.h"
#include "sockethelper/socket_helper.h"
#include "AndroidSdApi.h"

#define MAX_FILE_SIZE 2048
#define MAX_REQUEST_SIZE    1024*8

//for test
#define SERVER_IP       "172.16.2.198"
#define SERVER_PORT     8088

static const char *OS = "os=x86";
//static const char *VERSION="version=2.4.0.0";
static const char *VERSION="version=2.4.0";

static char responseData[MAX_REQUEST_SIZE] = {0};
static int responseLen = 0;

static char g_ip[32] = {0};
static int g_port = 0;

int g_debug = 0;

//检查版本号，可以不需要
int checkVersion(char *ip,int port);
//用户认证获取证书，密钥及配置文件
int checkUser(char *ip,int port,char *post_data);
//http请求发送函数
int sendUrl(char *url,char *post_data,void *save);
//处理base64中的加号
char *Test_Encode(char *source,int len);
//base64解码并保存文件
int saveFileBase64(char *filename,char *base64data);
//读取配置文件中的信息
int readConfFile(char *filename,char *ip,int *port);


//读取证书数据（提前反配好内存）
#if 1
int readCertTF(char *cert)
{
    unsigned long ret = 0;
    int g_dev = 0;

    ret = SDAPI_SetAppPath("/usr/mount/mmcblk0p1");

    ret = SDAPI_OpenDevice(&g_dev);
    if(ret != 0)
        return ERR_TF_OPEN;

    ret = SDAPI_Login(g_dev,"111111",6);
    if(ret != 0)
    {
        SDAPI_CloseDevice(&g_dev);
        return ERR_TF_LOGIN;
    }

    unsigned long rlen = 0;
    int index = 1;

    ret = SDAPI_ReadCertificate(g_dev,NULL,&rlen,index);
    if(rlen <=0 )
    {
        index = 0;
        ret = SDAPI_ReadCertificate(g_dev,NULL,&rlen,index);
        if(rlen <= 0)
        {
            SDAPI_CloseDevice(&g_dev);
            return ERR_TF_CERT;
        }
    }

    //printf("-------> read cert len = %ld\n",rlen);

    ret = SDAPI_ReadCertificate(g_dev,cert,&rlen,index);
    if(ret !=0 )
    {
        SDAPI_CloseDevice(&g_dev);
        return ERR_TF_CERT;
    }

    //printf("---->Read Cert Return %.8lX\n",ret);
#if 0
    FILE *fp;
    fp = fopen("test_cert.der","w+");
    if(fp == NULL)
    {
        printf("----->open Error.\n");
        return 0;
    }
    int wlen = fwrite(cert,1,rlen,fp);
    fclose(fp);
    printf("----->Write:%d\n",wlen);

    //读取序列号
    unsigned char sn[16] = {0};
    //unsigned long rlen = 0;
    rlen = 0;
    ret = SDAPI_ReadLaserSN(g_dev,sn);
    int i = 0;
    printf("----SN: %s\n",sn);
    for(i = 0 ; i < 16;i++)
        printf("%02x",sn[i]);

    printf("\n\n");
#endif

    ret = SDAPI_CloseDevice(&g_dev);
    return rlen;
}
#endif

int readCertTest(char *der_data,char *filename)
{
    //char der_data[2048] = {0};
    int der_len = 0;

    FILE *fp = NULL;
    fp = fopen(filename,"rb");
    if(fp == NULL)
    {
        perror("fopen");
        return 0;
    }
    der_len = fread(der_data,1,MAX_FILE_SIZE,fp);
    if(der_len <=0)
    {
        perror("fread.");
        return 0;
    }
    fclose(fp);
    return der_len;
}

int getRequest(void *buffer,size_t size,size_t nmemb,void *ptr)
{
    //printf("============\n");
    //memset(responseData,'\0',MAX_REQUEST_SIZE);
	if(responseLen+size*nmemb > MAX_REQUEST_SIZE)
	{
		responseLen = 0;
	}
    memcpy(responseData+responseLen,buffer,size*nmemb);
    responseLen += size*nmemb;
    //printf("%s\n",buffer);

    // write
    if(ptr != NULL)
    {
        FILE *fp = (FILE *)ptr;
        fwrite(buffer,size,nmemb,fp);
    }
    //printf("============\n");
    return size*nmemb;
}




/*************************************************************/

int verify_cert()
{
    int ret = ERR_OK;
    memset(g_ip,'\0',32);
    ret = readConfFile(CONF_FILE,g_ip,&g_port);
    if(ret < 0)
        return ret;
    if(g_debug)
    {
        printf("IP:%s\n",g_ip);
        printf("port:%d\n",g_port);
    }

	int tsock = mite_sock_openSocketByTimeout(g_ip,g_port,4);
	if(tsock <=0)
	{
        //printf("服务器端口未开放\n");
        return ERR_CONNECT_REFUSED;
	}
	close(tsock);

	/*
	tsock = mite_sock_openSocketByTimeout(g_ip,1194,4);
	if(tsock <=0)
	{
		printf("加密服务器端口未开放\n");
		return 0;
	}
	printf("加密服务器端口检查...[成功].\n");
	close(tsock);
	*/

    // [0] 如果有sslvpn已经在运行要先把他干掉
    // system("killall sslvpn");

    /*********************/
    //[1]读取公钥证书
    /*********************/
    char der_data[2048] = {0};
    int der_len = 0;

    //der_len = readCertTest(der_data,"test_cert.cer");
    der_len = readCertTF(der_data);

    if(der_len <0)
    {
        //printf("Read Cert Error.\n");
        return der_len;
    }

    /*********************/
    // [2] 将公钥证书做base64编码
    /*********************/
    char *base64_crt = NULL;
    int base64_len = 0;
    //base64_len = mite_base64_2_string_block(der_data,der_len,&base64_crt);
    base64_len = mite_string_2_base64_block(der_data,der_len,&base64_crt);

    if(base64_len > 0)
    {
        if(g_debug){
            FILE *f = NULL;
            f=fopen("cert_base64.der","w+");
            fwrite(base64_crt,1,base64_len,f);
            fclose(f);
        }
    }
    else
    {
        return ERR_CODEC;
    }

    /********************/
    // [3] 检查版本号(可选)
    /********************/
    int http_ret = 0;
#if 0
    //http_ret = checkVersion("192.168.1.120",80);
    //http_ret = checkVersion(SERVER_IP,SERVER_PORT);
    http_ret = checkVersion(g_ip,g_port);
    if(http_ret != 200)
    {
        printf("请求失败 [%d]\n",http_ret);
        return 0;
    }
    else
    {
        printf("获得数据[%d] %s\n",responseLen,responseData);
    }
#endif
    /********************/
    // [4] 认证用户
    /********************/
    /* [1]  os
     * [2] base64编码后的公钥证书
     * [3] ca   的 md5
     * [4] cert 的 md5
     * [5] key  的 md5
     */

    char post_data[2048] = {0};
    int pos = 0;


    char ca_md5[33] = {0};
    memset(ca_md5,'1',32);
    ca_md5[32] ='\0';
    CalFileMD5(M_CA_FILE,ca_md5);

    char cert_md5[33] = {0};
    memset(cert_md5,'2',32);
    cert_md5[32] ='\0';
    CalFileMD5(M_CERT_FILE,cert_md5);

    char key_md5[33] = {0};
    memset(key_md5,'3',32);
    key_md5[32] ='\0';
    CalFileMD5(M_KEY_FILE,key_md5);

    //char base64_codec[2048] = {0};
    //int rc = 0;
    //rc = u2g(base64_crt,base64_len,base64_codec,2048);

    char *base64_codec=NULL;
    base64_codec = Test_Encode(base64_crt,base64_len);
    //curl_free(base64_codec);

    //sprintf(post_data,"osType=%s&certificate=%s&ca_file_md5=%s&cert_file_md5=%s&key_file_md5=%s","x86",base64_crt,ca_md5,cert_md5,key_md5);
    sprintf(post_data,"osType=%s&certificate=%s&ca_file_md5=%s&cert_file_md5=%s&key_file_md5=%s","x86",base64_codec,ca_md5,cert_md5,key_md5);

    //printf("POST : %s\n",post_data);

    http_ret = checkUser(g_ip,g_port,post_data);

   if(base64_crt != NULL)
       free(base64_crt);
   if(base64_codec != NULL)
       curl_free(base64_codec);

    if(http_ret != 200)
    {
        return ERR_REQUEST;
    }

    /********************/
    // [5] 检查返回标志，如果不匹配需要保存相关文件
    /********************/
   // "success":true , 认证成功
   // "success":false , 认证失败，取msg字段
   // "compare":true  ,   数据匹配成功不需要下载
   // "compare":false ,   数据匹配失败，需要下载
   //保存相关文件
   // (1) ca     -> /etc/data1.data
   // (2) cert   -> /etc/data2.data
   // (3) key    -> /etc/data3.data
   // (4) config -> /etc/data4.data

    JSON_INFO *info = NULL;
    info = json_ParseString(responseData);
	if(!info)
	{
        //printf("Can not prase Server Msg.\n");
        return ERR_CODEC_J;
	}

    if(g_debug)
    {
        json_Print(info);
    }

    int verify = json_getBool(info,"success");
    if(verify == JSON_TRUE)
    {
        printf("Verify_OK.\n");
    }
    else
    {
        printf("Verify_Fail.\n");
        json_Delete(info);
        return ERR_VERIFY_FAIL;
    }

    int comp = json_getBool(info,"compare");
    if(comp == JSON_TRUE)
    {
        printf("Compare Success.\n");
        json_Delete(info);
        return ERR_OK;
    }else
    {
        printf("Compare Fail.\n");
    }

    int save_ret = 0;
    //(1) ca
    char *ca = NULL;
    ca = json_getString(info,"ca");
    save_ret |= saveFileBase64(M_CA_FILE,ca+1);
    //(2) cert
    char *crt = NULL;
    crt = json_getString(info,"crt");
    save_ret |= saveFileBase64(M_CERT_FILE,crt+1);
    //(3) key
    char *key = NULL;
    key = json_getString(info,"key");
    save_ret |= saveFileBase64(M_KEY_FILE,key+1);
    //(4) config
    char *config = NULL;
    config = json_getString(info,"config");
    save_ret |= saveFileBase64(M_CONFIG_FILE,config+1);

    if(save_ret != 0)
    {
        json_Delete(info);
        return ERR_NET_CONFIG;
    }

    json_Delete(info);

    return ERR_OK;
}



int checkVersion(char *ip,int port)
{
    //http://192.168.1.120/UpgradeVersionAction_check.action?os=x86&version=2.4.0
    char url[1024] = {0};
    char post_data[2048] = {0};
    char *action = "/UpgradeVersionAction_check.action?";

    FILE *fp = NULL;
    fp = fopen("check_verion.json","w+");
    if(fp== NULL)
    {
        perror("fopen:");
        return -1;
    }

    sprintf(url,"http://%s:%d%s",ip,port,action);
    sprintf(post_data,"os=%s&version=%s",M_OS,M_VERSION);

    int rtCode = 0;
 #if 0
    {
        FILE *f = NULL;
        f = fopen("http_check.txt","w+");
        fwrite(url,1,strlen(url),f);
        fwrite('?',1,strlen(url),f);
        fwrite(post_data,1,strlen(url),f);
    }
 #endif
    //printf("url:%s\n",url);
    //printf("post:%s\n",post_data);

    rtCode = sendUrl(url,post_data,fp);
    printf("%s%s [%d]\n",url,post_data,rtCode);

    fclose(fp);

    //handle json
    return rtCode;
}


int checkUser(char *ip,int port,char *post_data)
{
    char url[1024] = {0};
    //char post_data[4096] = 0;
    char *action = "/CheckAction_check.action";

    FILE *fp = NULL;
    if(g_debug)
    {
        fp = fopen("check_user.json","w+");
        if(fp== NULL)
        {
            perror("fopen:");
            return -1;
        }
    }
    sprintf(url,"http://%s:%d%s",ip,port,action);
    /* post data
     * [1] os
     * [2] base64编码后的公钥证书
     * [3] ca   的 md5
     * [4] cert 的 md5
     * [5] key  的 md5
     *
     */
    //sprintf(post_data,"%s&%s",OS,VERSION);

    int rtCode = 0;
    rtCode = sendUrl(url,post_data,fp);
    if(g_debug)
    {
        printf("%s [%d]\n",url,rtCode);
        fclose(fp);
    }

    //handle json
    return rtCode;
}


int sendUrl(char *url,char *post_data,void *save)
{
    CURL *curl;
    CURLcode res;
    int resp_code = 0;

    curl = curl_easy_init();
	memset(responseData,'\0',MAX_REQUEST_SIZE);
	responseLen = 0;
    if(NULL != curl)
    {
           curl_easy_setopt(curl,CURLOPT_URL,url);
           curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,getRequest);
           curl_easy_setopt(curl,CURLOPT_WRITEDATA,save);

           curl_easy_setopt(curl,CURLOPT_POSTFIELDS,post_data);
           curl_easy_setopt(curl,CURLOPT_POST,1);

           res = curl_easy_perform(curl);
    }else
        return -1;

    if(res == CURLE_OK)
    {
        res= curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&resp_code);
        if(res == CURLE_OK)
        {
        }
    }
    else
    {
        fprintf(stderr,"Error :%s\n",curl_easy_strerror(res));
        resp_code = 0;
    }

    curl_easy_cleanup(curl);
    return resp_code;
}






//need to free
char *Test_Encode(char *source,int len)
{
    CURL *curl = curl_easy_init();
    char *cres = curl_easy_escape(curl,source,len);
    //string res(cres);
    //curl_free(cres);
    curl_easy_cleanup(curl);
    return cres;
}




int saveFileBase64(char *filename,char *base64data)
{
    FILE *fp = NULL;
    fp = fopen(filename,"w+");
    if(fp == NULL)
    {
        perror("fopen");
        return -1;
    }
    int ret = 0;
    char *data=NULL;
    int datalen = 0 ;

    datalen = mite_base64_2_string_block(base64data,strlen(base64data)-1,&data);
    //printf("len[%d]\n",datalen);
    //printf("data[%s]\n",data);
    ret = fwrite(data,1,datalen,fp);
    fclose(fp);
    if(ret <= 0 )
    {
        perror("fwrite");
        return -1;
    }else
    {
        free(data);
        return 0;
    }
}

int readConfFile(char *filename,char *ip,int *port)
{
	FILE *fp = NULL;
	char* ret = NULL;
	fp = fopen(filename,"rb");
	if(fp == NULL)
	{
		perror("fopen");
        return ERR_NO_CONFIG;
    }

	char *line;
	line = malloc(1024);
    memset(ip,'\0',1);
	while(1)
	{
		memset(line,'\0',1024);
		fflush(0);
		if(fp != NULL){
			ret = fgets(line,1024,fp);
		}
		if(ret == NULL || strlen(line) <= 0) {
			break;
		}
		if(line[0] == '#')
		{
			continue;
		}
		line[strlen(line)-1] = '\0';
		if(strstr(line,CONF_SERVER_IP))
		{
			strcpy(ip,line+strlen(CONF_SERVER_IP)+1);
			continue;
		}
		
		if(strstr(line,CONF_SERVER_PORT))
		{
			*port = atoi(line+strlen(CONF_SERVER_PORT)+1);
			continue;
		}
	}
    free(line);
    fclose(fp);
    if((strlen(ip)<2) || port < 0)
    {
        return ERR_BAD_CONFIG;
    }

    return 0;
}



//test
#if 1
int main(int argc,char *argv[])
{
    if(argc >= 2)
        g_debug = 1;
	int ret = 0;
    if((ret=verify_cert())==0)
    {
        printf("用户认证成功.\n");
    }else
    {
        printf("用户认证失败[%d].\n",ret);
    }
    return 0;
}
#endif
