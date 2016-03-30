#include <stdio.h>
#include <stdlib.h>
#include "json/cJSON.h"
#include "json_handler.h"






#if 0
int main(void)
{
    char data[2048] = {0};
	/*
    FILE *fp = NULL;
    fp = fopen("version.json","r");
    int read_len = 0;
    read_len = fread(data,1,1024,fp);
    fclose(fp);

    printf("read[%d] %s\n",read_len,data);
	*/
	sprintf(data,"%s","{\"name\":\"sslvpn\",\"version\":\"2.4.0\"}");

    cJSON *root = cJSON_Parse(data);
    if(!root)
    {
        printf("error Parse!!!\n");
        return 0;
    }


    //add
    cJSON *hello;
    hello=cJSON_CreateString("hw");
    cJSON_AddItemToObject(root,"arm_test",hello);



	#if 0
    cJSON *name = NULL;
    name = cJSON_GetObjectItem(root,"name");
    char *name_str=NULL;
    name_str = cJSON_Print(name);

    printf("***************\n");
    printf("name = %s\n",name_str);
    //free(name);   只是取指针，不用释放
    cJSON *length_o;
    length_o = cJSON_GetObjectItem(root,"length");
    int length;
    if(length_o->type==cJSON_Number)
        printf("length = %d.\n",length_o->valueint);

    cJSON *obj_flag;
    obj_flag = cJSON_GetObjectItem(root,"flag");
    if(obj_flag->type == cJSON_True)
    {
        printf("FLAG is True.\n");
    }else
    {
        printf("FLAG is Flase.\n");
    }
    printf("***************\n");
	#endif



    char *out;
    out = cJSON_Print(root);
    printf("%s\n",out);
    free(out);


    cJSON_Delete(root);




    return 0;
}
#endif


JSON_INFO *json_ParseFile(char *filename)
{
    char data[MAX_DATA] = {0};
    FILE *fp = NULL;
    fp = fopen(filename,"r");
    if(!fp)
    {
        printf("Open Fail.\n");
        return NULL;
    }
    int read_len = 0;
    read_len = fread(data,1,MAX_DATA,fp);
    if(read_len <=0 )
    {
        printf("Read Error.\n");
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    return json_ParseString(data);
}


JSON_INFO *json_ParseString(char *json_string)
{
    JSON_INFO *info = malloc(sizeof(JSON_INFO));
    info->root = cJSON_Parse(json_string);
    return info;
}


void json_Print(JSON_INFO *info)
{
    char *out;
    out = cJSON_Print(info->root);
    printf("%s\n",out);
}

void json_Delete(JSON_INFO *info)
{
    if(info->root)
        cJSON_Delete(info->root);

    free(info);
}



char *json_getString(JSON_INFO *info, char *key)
{
    cJSON *node = NULL;
    node = cJSON_GetObjectItem(info->root,key);
    char *ret_string = NULL;
    ret_string = cJSON_Print(node);

    return ret_string;
}

int json_getBool(JSON_INFO *info, char *key)
{
    cJSON *node = NULL;
    node = cJSON_GetObjectItem(info->root,key);
    if(node->type == cJSON_True)
    {
        return JSON_TRUE;
    }else
    {
        return JSON_FALSE;
    }
}





