#include <ngx_core.h>
#include <ngx_http.h>
#include <lauxlib.h>
#include <zookeeper/zookeeper.h>

#include "ngx_http_lua_api.h"

#define CAST(p, T) ((T)p)

ngx_module_t ngx_zookeeper_lua_module;

static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf);

static char *
ngx_http_zookeeper_lua_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_int_t
ngx_zookeeper_lua_init(ngx_conf_t *cf);
static int
ngx_zookeeper_lua_create_module(lua_State * L);

ngx_int_t
ngx_zookeeper_lua_init_worker(ngx_cycle_t *cycle);
void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle);

static char *
ngx_http_zookeeper_lua_hosts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_zookeeper_lua_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_zookeeper_lua_recv_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct
{
    ngx_str_t hosts;
    ngx_int_t recv_timeout;
    ZooLogLevel log_level;
} ngx_http_zookeeper_lua_module_main_conf_t;

static ngx_command_t ngx_http_zookeeper_lua_commands[] = {
    { ngx_string("zookeeper"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_zookeeper_lua_hosts,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_zookeeper_lua_log_level,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_recv_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_zookeeper_lua_recv_timeout,
      0,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_zookeeper_lua_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_zookeeper_lua_init,                 /* postconfiguration */
    ngx_http_zookeeper_lua_create_main_conf,/* create main configuration */
    ngx_http_zookeeper_lua_init_main_conf,  /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};

ngx_module_t ngx_zookeeper_lua_module = {
    NGX_MODULE_V1,
    &ngx_zookeeper_lua_ctx,              /* module context */
    ngx_http_zookeeper_lua_commands,     /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    ngx_zookeeper_lua_init_worker,       /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    ngx_zookeeper_lua_exit_worker,       /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zookeeper_lua_module_main_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->log_level = ZOO_LOG_LEVEL_ERROR;
    conf->recv_timeout = 10000;

    return conf;
}

static char *
ngx_http_zookeeper_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

static char *
ngx_http_zookeeper_lua_hosts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = conf;
    ngx_str_t *values = cf->args->elts;

    zookeeper_conf->hosts.data = ngx_pcalloc(cf->pool, values[1].len + 1);
    if (zookeeper_conf->hosts.data == NULL)
    {
        return NULL;
    }
    memcpy(zookeeper_conf->hosts.data, values[1].data, values[1].len);
    zookeeper_conf->hosts.len = values[1].len;

    return NGX_CONF_OK;
}

static char *
ngx_http_zookeeper_lua_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = conf;
    ngx_str_t *values = cf->args->elts;

    if (ngx_strncasecmp(CAST("error", u_char*), values[1].data, 5) == 0)
    {
        zookeeper_conf->log_level = ZOO_LOG_LEVEL_ERROR;
    } else if (ngx_strncasecmp(CAST("warn", u_char*), values[1].data, 4) == 0)
    {
        zookeeper_conf->log_level = ZOO_LOG_LEVEL_WARN;
    } else if (ngx_strncasecmp(CAST("info", u_char*), values[1].data, 4) == 0)
    {
        zookeeper_conf->log_level = ZOO_LOG_LEVEL_INFO;
    } else if (ngx_strncasecmp(CAST("debug", u_char*), values[1].data, 5) == 0)
    {
        zookeeper_conf->log_level = ZOO_LOG_LEVEL_DEBUG;
    } else
    {
        return "invalid zookeeper_log_level value (error, warn, info, debug)";
    }

    zoo_set_debug_level(zookeeper_conf->log_level);

    return NGX_CONF_OK;
}

static char *
ngx_http_zookeeper_lua_recv_timeout(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = conf;
    ngx_str_t *values = cf->args->elts;

    zookeeper_conf->recv_timeout = ngx_atoi(values[1].data, values[1].len);
    if (zookeeper_conf->recv_timeout == (ngx_int_t) NGX_ERROR || zookeeper_conf->recv_timeout < 1 || zookeeper_conf->recv_timeout > 60000)
    {
        return "invalid value (1-60000 mseconds)";
    }

    return NGX_CONF_OK;
}

typedef struct
{
    zhandle_t *handle;
    int connected;
    const clientid_t *client_id;
} zookeeper_t;

static zookeeper_t zoo = {
    .handle = NULL,
    .connected = 0,
    .client_id = NULL
};

ngx_int_t
ngx_zookeeper_lua_init(ngx_conf_t *cf)
{
    if (ngx_http_lua_add_package_preload(cf, "ngx.zookeeper",
                                         ngx_zookeeper_lua_create_module)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void ngx_log_message(const char *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, s);
}

static const char *str_type(int type)
{
    if (type == ZOO_CREATED_EVENT)
        return "CREATED_EVENT";
    if (type == ZOO_DELETED_EVENT)
        return "DELETED_EVENT";
    if (type == ZOO_CHANGED_EVENT)
        return "CHANGED_EVENT";
    if (type == ZOO_CHILD_EVENT)
        return "CHILD_EVENT";
    if (type == ZOO_SESSION_EVENT)
        return "SESSION_EVENT";
    if (type == ZOO_NOTWATCHING_EVENT)
        return "NOTWATCHING_EVENT";
    
    return "UNKNOWN_EVENT_TYPE";
}

static const char *rc_str(int rc)
{
    if (rc == ZOK) {
        return "OK";
    }
    if (rc == ZSYSTEMERROR) {
        return "System error";
    }
    if (rc == ZRUNTIMEINCONSISTENCY) {
        return "Runtime inconsistency";
    }
    if (rc == ZDATAINCONSISTENCY) {
        return "Data inconsistency";
    }
    if (rc == ZCONNECTIONLOSS) {
        return "Connection to the server has been lost";
    }
    if (rc == ZMARSHALLINGERROR) {
        return "Error while marshalling or unmarshalling data ";
    }
    if (rc == ZUNIMPLEMENTED) {
        return "Operation not implemented";
    }
    if (rc == ZOPERATIONTIMEOUT) {
        return "Operation timeout";
    }
    if (rc == ZBADARGUMENTS) {
        return "Invalid argument";
    }
    if (rc == ZINVALIDSTATE) {
        return "Invalid zhandle state";
    }
    if (rc == ZAPIERROR) {
        return "API error";
    }
    if (rc == ZNONODE) {
        return "Znode does not exist";
    }
    if (rc == ZNOAUTH) {
        return "Not authenticated";
    }
    if (rc == ZBADVERSION) {
        return "Version conflict";
    }
    if (rc == ZNOCHILDRENFOREPHEMERALS) {
        return "Ephemeral nodes may not have children";
    }
    if (rc == ZNODEEXISTS) {
        return "Znode already exists";
    }
    if (rc == ZNOTEMPTY) {
        return "The znode has children";
    }
    if (rc == ZSESSIONEXPIRED) {
        return "The session has been expired by the server";
    }
    if (rc == ZINVALIDCALLBACK) {
        return "Invalid callback specified";
    }
    if (rc == ZINVALIDACL) {
        return "Invalid ACL specified";
    }
    if (rc == ZAUTHFAILED) {
        return "Client authentication failed";
    }
    if (rc == ZCLOSING) {
        return "ZooKeeper session is closing";
    }
    if (rc == ZNOTHING) {
        return "No response from server";
    }
    if (rc == ZSESSIONMOVED) {
        return "Session moved to a different server";
    }

    return "UNKNOWN_EVENT_TYPE";
}

static void
session_watcher(zhandle_t *zh,
                int type,
                int state,
                const char *path,
                void* context);

static ngx_int_t
initialize(volatile ngx_cycle_t *cycle)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    if (!zookeeper_conf || zookeeper_conf->hosts.len == 0)
    {
        return NGX_OK;
    }

    zoo.handle = zookeeper_init2(CAST(zookeeper_conf->hosts.data, const char*),
                                 session_watcher,
                                 zookeeper_conf->recv_timeout,
                                 zoo.client_id,
                                 0,
                                 0,
                                 ngx_log_message);

    if (!zoo.handle)
    {
        u_char err[1024];
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "Zookeeper: error create zookeeper handle: %s", ngx_strerror(errno, err, sizeof(err)));
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been initialized");

    return NGX_OK;
}

static void
session_watcher(zhandle_t *zh,
                int type,
                int state,
                const char *path,
                void* context)
{
    if (type == ZOO_SESSION_EVENT)
    {
        if (state == ZOO_CONNECTED_STATE)
        {
            zoo.connected = 1;
            zoo.client_id = zoo_client_id(zh);
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "Zookeeper: received a connected event");
        } else if (state == ZOO_CONNECTING_STATE)
        {
            if (zoo.connected == 1)
            {
                ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                              "Zookeeper: disconnected");
            }
            zoo.connected = 0;
        } else if (state == ZOO_EXPIRED_SESSION_STATE)
        {
            if (zh != NULL)
            {
                ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                              "Zookeeper: session has been expired");
                zookeeper_close(zh);
                bzero(&zoo, sizeof(zoo));
            }
            initialize(ngx_cycle);
        }
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "Zookeeper event: %s, %d",
                   str_type(type), state);
}

ngx_int_t
ngx_zookeeper_lua_init_worker(ngx_cycle_t *cycle)
{
    return initialize(cycle);
}

void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle)
{
    int rc;

    if (!zoo.handle)
    {
        return;
    }

    rc = zookeeper_close(zoo.handle);
    if (rc != ZOK)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "Zookeeper close connection error: %s", rc_str(rc));
    }

    zoo.handle = NULL;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been destroyed");
}

static int ngx_zookeeper_aget(lua_State * L);
static int ngx_zookeeper_aset(lua_State * L);
static int ngx_zookeeper_aget_childrens(lua_State * L);
static int ngx_zookeeper_acreate(lua_State * L);
static int ngx_zookeeper_adelete(lua_State * L);
static int ngx_zookeeper_check_completition(lua_State * L);

static int
ngx_zookeeper_lua_create_module(lua_State * L)
{
    lua_createtable(L, 0, 6);

    lua_pushcfunction(L, ngx_zookeeper_aget);
    lua_setfield(L, -2, "aget");

    lua_pushcfunction(L, ngx_zookeeper_aset);
    lua_setfield(L, -2, "aset");

    lua_pushcfunction(L, ngx_zookeeper_aget_childrens);
    lua_setfield(L, -2, "achildrens");

    lua_pushcfunction(L, ngx_zookeeper_acreate);
    lua_setfield(L, -2, "acreate");

    lua_pushcfunction(L, ngx_zookeeper_adelete);
    lua_setfield(L, -2, "adelete");

    lua_pushcfunction(L, ngx_zookeeper_check_completition);
    lua_setfield(L, -2, "check_completition");

    return 1;
}

static int
ngx_zookeeper_lua_error(lua_State * L, const char *where, const char *error)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp) - 1, "%s: %s", where, error);
    lua_pushboolean(L, 0);
    lua_pushlstring(L, tmp, strlen(tmp));
    return 2;
}

static int
ngx_zookeeper_aget(lua_State * L)
{
    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "aget", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "aget", "not connected");
    }

    return ngx_zookeeper_lua_error(L, "aget", "unsupported");
}

static int
ngx_zookeeper_aset(lua_State * L)
{
    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "aset", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "aset", "not connected");
    }

    return ngx_zookeeper_lua_error(L, "aset", "unsupported");
}

static int
ngx_zookeeper_aget_childrens(lua_State * L)
{
    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "aget_childrens", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "aget_childrens", "not connected");
    }

    return ngx_zookeeper_lua_error(L, "aget_childrens", "unsupported");
}

static int
ngx_zookeeper_acreate(lua_State * L)
{
    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "not connected");
    }

    return ngx_zookeeper_lua_error(L, "acreate", "unsupported");
}

static int
ngx_zookeeper_adelete(lua_State * L)
{
    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "adelete", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "adelete", "not connected");
    }

    return ngx_zookeeper_lua_error(L, "adelete", "unsupported");
}

static int
ngx_zookeeper_check_completition(lua_State * L)
{
    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "check_completition", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "check_completition", "not connected");
    }

    return ngx_zookeeper_lua_error(L, "check_completition", "unsupported");
}
