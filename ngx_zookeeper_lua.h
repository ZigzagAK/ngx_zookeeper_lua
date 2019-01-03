#ifndef _ngx_zookeeper_lua_h_
#define _ngx_zookeeper_lua_h_


#include <ngx_config.h>


ngx_flag_t ngx_zookeeper_lua_connected();
int ngx_zookeeper_lua_epoch();
void * ngx_zookeeper_lua_handle();

#endif
