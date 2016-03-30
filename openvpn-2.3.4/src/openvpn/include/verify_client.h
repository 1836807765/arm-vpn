#ifndef __VERIFY_CLIENT_H__
#define __VERIFY_CLIENT_H__

int verify_Hardcert();
void set_debug();
int watch_process(char *file);
void kill_all(char *file);
int getSslAddress(char *file,char *ip,int *port);
#endif
