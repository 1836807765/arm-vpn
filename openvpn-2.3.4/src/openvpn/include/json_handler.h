#ifndef __JSON_HANDLER_H__
#define __JSON_HANDLER_H__
#include "json/cJSON.h"

#define MAX_DATA    1024*8

#define JSON_TRUE   0
#define JSON_FALSE  1

typedef struct _json_info
{
    cJSON *root;

}JSON_INFO;


JSON_INFO* json_ParseFile(char *filename);
JSON_INFO* json_ParseString(char *json_string);

void json_Print(JSON_INFO *info);
void json_Delete(JSON_INFO *info);



char *json_getString(JSON_INFO *info,char *key);

int json_getBool(JSON_INFO *info,char *key);


#endif
