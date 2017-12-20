#include <ngx_core.h>

#include <ngx_http.h>
#include <lauxlib.h>
#include <assert.h>
#include <zookeeper/zookeeper.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

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
static char *
ngx_http_zookeeper_lua_read_only(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_zookeeper_lua_ethemeral_node(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_http_zookeeper_lua_register_port(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct
{
    ngx_str_t hosts;
    ngx_int_t recv_timeout;
    int init_flags;
    ngx_array_t *nodes;
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

    { ngx_string("zookeeper_ethemeral_node"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_zookeeper_lua_ethemeral_node,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_register_port"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_zookeeper_lua_register_port,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_read_only"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_NOARGS,
      ngx_http_zookeeper_lua_read_only,
      0,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_zookeeper_lua_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_zookeeper_lua_init,                  /* postconfiguration */
    ngx_http_zookeeper_lua_create_main_conf, /* create main configuration */
    ngx_http_zookeeper_lua_init_main_conf,   /* init main configuration */
    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */
    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
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

struct ethemeral_node_s {
    ngx_array_t *path;
    ngx_str_t value;
    ngx_str_t instance;
    ngx_str_t data;
    int epoch;
};
typedef struct ethemeral_node_s ethemeral_node_t;

static char ip_address[128] = "?.?.?.?";

static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *conf;
    struct utsname host;
    struct addrinfo *servinfo, hints, *p;
    struct sockaddr_in *h;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zookeeper_lua_module_main_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->log_level = ZOO_LOG_LEVEL_ERROR;
    conf->recv_timeout = 10000;
    conf->init_flags = 0;
    conf->nodes = ngx_array_create(cf->pool, 1000, sizeof(ethemeral_node_t));

    if (0 == uname(&host))
    {
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (0 == getaddrinfo(host.nodename, NULL, &hints, &servinfo))
        {
            for (p = servinfo; p != NULL; p = p->ai_next)
            {
                h = (struct sockaddr_in *) p->ai_addr;
                if (h->sin_addr.s_addr != 0)
                {
                    strncpy(ip_address, inet_ntoa(h->sin_addr), sizeof(ip_address) - 1);
                    break;
                }
            }
        }
    }

    freeaddrinfo(servinfo);
    servinfo = NULL;

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

static char *
ngx_http_zookeeper_lua_read_only(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = conf;
    // Temporary unsupported
    // zookeeper_conf->init_flags = ZOO_READONLY;
    return NGX_CONF_OK;
}

static char *
ngx_http_zookeeper_lua_ethemeral_node(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = conf;
    ngx_str_t *values = cf->args->elts;
    ethemeral_node_t *node;
    char *s;
    ngx_str_t *subpath;

    node = ngx_array_push(zookeeper_conf->nodes);

    node->path = ngx_array_create(cf->pool, 1000, sizeof(ngx_str_t));

    for (s = ngx_strchr(values[1].data + 1, '/'); s; s = ngx_strchr(s + 1, '/'))
    {
        subpath = ngx_array_push(node->path);
        subpath->len = (u_char *)s - values[1].data;
        subpath->data = ngx_pcalloc(cf->pool, subpath->len + 1);
        ngx_memcpy(subpath->data, values[1].data, subpath->len);
    }

    subpath = ngx_array_push(node->path);
    subpath->data = values[1].data;
    subpath->len = values[1].len;

    node->value = values[2];

    node->instance.len = values[1].len + node->value.len + 1;
    node->instance.data = ngx_pcalloc(cf->pool, node->instance.len + 1);
    if (node->instance.data == NULL)
    {
        return NULL;
    }

    ngx_snprintf(node->instance.data, node->instance.len + 1, "%s/%s", values[1].data, node->value.data);

    node->epoch = 0;

    if (cf->args->nelts == 4)
    {
        node->data.len = values[3].len;
        node->data.data = ngx_pcalloc(cf->pool, node->data.len + 1);
        if (node->data.data == NULL)
        {
            return NULL;
        }
        ngx_memcpy(node->data.data, values[3].data, node->data.len);
    }
    else
    {
        node->data.data = (u_char *) "";
        node->data.len = 0;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_zookeeper_lua_register_port(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = conf;
    ngx_str_t *values = cf->args->elts;
    ethemeral_node_t *node;
    char *s;
    ngx_str_t *subpath;

    node = ngx_array_push(zookeeper_conf->nodes);

    node->path = ngx_array_create(cf->pool, 1000, sizeof(ngx_str_t));

    for (s = ngx_strchr(values[1].data + 1, '/'); s; s = ngx_strchr(s + 1, '/'))
    {
        subpath = ngx_array_push(node->path);
        subpath->len = (u_char *)s - values[1].data;
        subpath->data = ngx_pcalloc(cf->pool, subpath->len + 1);
        ngx_memcpy(subpath->data, values[1].data, subpath->len);
    }

    subpath = ngx_array_push(node->path);
    subpath->data = values[1].data;
    subpath->len = values[1].len;

    node->value.len = ngx_strlen(ip_address) + values[2].len + 1;
    node->value.data = ngx_pcalloc(cf->pool, node->value.len + 1);
    ngx_snprintf(node->value.data, node->value.len, "%s:%s", ip_address, values[2].data);

    node->instance.len = values[1].len + node->value.len + 1;
    node->instance.data = ngx_pcalloc(cf->pool, node->instance.len + 1);
    if (node->instance.data == NULL)
    {
        return NULL;
    }

    ngx_snprintf(node->instance.data, node->instance.len + 1, "%s/%s", values[1].data, node->value.data);

    node->epoch = 0;

    if (cf->args->nelts == 4)
    {
        node->data.len = values[3].len;
        node->data.data = ngx_pcalloc(cf->pool, node->data.len + 1);
        if (node->data.data == NULL)
        {
            return NULL;
        }
        ngx_memcpy(node->data.data, values[3].data, node->data.len);
    }
    else
    {
        node->data.data = (u_char *) "";
        node->data.len = 0;
    }

    return NGX_CONF_OK;
}

typedef struct
{
    zhandle_t *handle;
    int connected;
    const clientid_t *client_id;
    int expired;
    int epoch;
} zookeeper_t;

static zookeeper_t zoo = {
    .handle = NULL,
    .connected = 0,
    .client_id = NULL,
    .expired = 1,
    .epoch = 1
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

static void
ngx_log_message(const char *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, s);
}

#if (NGX_DEBUG)

static const char *
str_type(int type)
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

#endif

static const char *
rc_str_s(int rc)
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

static const u_char *
rc_str(int rc)
{
    return (const u_char *)rc_str_s(rc);
}

static void
ngx_zookeeper_register_ready(int rc, const char *value, const void *data)
{
    ethemeral_node_t *node = (ethemeral_node_t *) data;

    if (rc != ZOK)
    {
        if (rc != ZNODEEXISTS)
        {
            if (data)
            {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "Zookeeper can't register ephemeral node %s : %s", node->instance.data, rc_str_s(rc));
            }
            else
            {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "Zookeeper can't create node : %s", rc_str_s(rc));
            }
        }
        return;
    }

    if (data)
    {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "Nginx has been registered, instance: %s", node->instance.data);

        node->epoch = zoo.epoch;
    }

    return;
}

static void
initialize(volatile ngx_cycle_t *cycle);

static void
ngx_zookeeper_delete_ready(int rc, const void *data);

static void
ngx_zookeeper_register_callback(ngx_event_t *ev)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_zookeeper_lua_module);
    ethemeral_node_t *nodes = (ethemeral_node_t *)zookeeper_conf->nodes->elts;
    int rc;
    ngx_uint_t i, j;
    ngx_str_t *path;

    if (zoo.expired == 1)
    {
        if (zoo.handle)
        {
            zookeeper_close(zoo.handle);
            zoo.handle = NULL;
            zoo.client_id = 0;
        }
        initialize(ngx_cycle);
    }

    if (zookeeper_conf->nodes->nelts == 0)
    {
        goto settimer;
    }

    if (zoo.connected == 0)
    {
        goto settimer;
    }

    for (i = 0; i < zookeeper_conf->nodes->nelts; ++i)
    {
        if (zoo.epoch > nodes[i].epoch)
        {
            zoo_adelete(zoo.handle, (const char *)nodes[i].instance.data, -1, ngx_zookeeper_delete_ready, NULL);

            path = (ngx_str_t *)nodes[i].path->elts;

            for (j = 0; j < nodes[i].path->nelts; ++j)
            {
                rc = zoo_acreate(zoo.handle, (const char *)path[j].data, "", 0,
                                &ZOO_OPEN_ACL_UNSAFE, 0, ngx_zookeeper_register_ready, NULL);

                if (rc != ZOK)
                {
                    ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                                  "Zookeeper: error create node %s : %s", path[j].data, rc_str_s(rc));
                }
            }

            rc = zoo_acreate(zoo.handle, (const char *)nodes[i].instance.data, (const char *)nodes[i].data.data, nodes[i].data.len,
                            &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, ngx_zookeeper_register_ready, &nodes[i]);

            if (rc != ZOK)
            {
                ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                              "Zookeeper: error register instance: %s", rc_str_s(rc));
            }
        }
    }

settimer:

    if (ngx_exiting)
    {
        // cleanup
        ngx_memset(ev, 0, sizeof(ngx_event_t));
    }
    else
    {
        ngx_add_timer(ev, zookeeper_conf->recv_timeout * 2);
    }
}

static void
ngx_zookeeper_create_ready(int rc, const char *value, const void *data);

static void
session_watcher(zhandle_t *zh,
                int type,
                int state,
                const char *path,
                void* context);

static ngx_connection_t dumb_conn = {
    .fd = -1
};
static ngx_event_t register_ev = {
    .handler = ngx_zookeeper_register_callback,
    .data = &dumb_conn,
    .log = NULL
};

static void
initialize(volatile ngx_cycle_t *cycle)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    zoo.handle = zookeeper_init2(CAST(zookeeper_conf->hosts.data, const char*),
                                 session_watcher,
                                 zookeeper_conf->recv_timeout,
                                 zoo.client_id,
                                 0,
                                 zookeeper_conf->init_flags,
                                 ngx_log_message);

    if (!zoo.handle)
    {
        u_char err[1024];
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "Zookeeper: error create zookeeper handle: %s", ngx_strerror(errno, err, sizeof(err)));
        return;
    }

    zoo.expired = 0;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper: connecting ...");
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
            zoo.epoch = zoo.epoch + 1;
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
                zoo.connected = 0;
                zoo.expired = 1;
            }
        }
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "Zookeeper event: %s, %d",
                   str_type(type), state);
}

ngx_int_t
ngx_zookeeper_lua_init_worker(ngx_cycle_t *cycle)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    if (zookeeper_conf == NULL || zookeeper_conf->hosts.len == 0)
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been initialized in %s mode", zookeeper_conf->init_flags == ZOO_READONLY ? "read only" : "read/write");

    initialize(cycle);

    if (ngx_worker == 0)
    {
        register_ev.log = cycle->log;
        ngx_add_timer(&register_ev, 2000);
    }

    return NGX_OK;
}

void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle)
{
    int rc;

    if (register_ev.log != NULL)
    {
        ngx_del_timer(&register_ev);
        ngx_memset(&register_ev, 0, sizeof(ngx_event_t));
    }

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

static int ngx_zookeeper_connected(lua_State * L);
static int ngx_zookeeper_aget(lua_State * L);
static int ngx_zookeeper_aset(lua_State * L);
static int ngx_zookeeper_aget_childrens(lua_State * L);
static int ngx_zookeeper_acreate(lua_State * L);
static int ngx_zookeeper_adelete(lua_State * L);
static int ngx_zookeeper_check_completition(lua_State * L);
static int ngx_zookeeper_timeout(lua_State * L);
static int ngx_zookeeper_forgot(lua_State * L);

static int
ngx_zookeeper_lua_create_module(lua_State * L)
{
    lua_createtable(L, 0, 9);

    lua_pushcfunction(L, ngx_zookeeper_connected);
    lua_setfield(L, -2, "connected");

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

    lua_pushcfunction(L, ngx_zookeeper_timeout);
    lua_setfield(L, -2, "timeout");

    lua_pushcfunction(L, ngx_zookeeper_forgot);
    lua_setfield(L, -2, "forgot");

    return 1;
}

static int
ngx_zookeeper_lua_error(lua_State * L, const char *where, const char *error)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp) - 1, "%s: %s", where, error);
    lua_pushnil(L);
    lua_pushlstring(L, tmp, strlen(tmp));
    return 2;
}

typedef struct
{
    const char *data;
    ngx_uint_t len;
} str_t;

typedef ngx_str_t string_result_t;

struct get_childs_result_s
{
    ngx_str_t *array;
    int count;
};
typedef struct get_childs_result_s get_childs_result_t;

typedef void (*completition_t)(lua_State * L, void *data);

struct result_s
{
    int completed;
    int forgotten;
    struct Stat stat;
    ngx_atomic_t lock;
    //---------------
    void *data;
    completition_t completition_fn;
    const char *error;
};
typedef struct result_s result_t;

static void
spinlock_lock(ngx_atomic_t *lock)
{
    int j;

    for (j = 0;;++j)
    {
        if (ngx_atomic_cmp_set(lock, 0, 1))
        {
            break;
        }

        if (j % 1000 == 0)
        {
            ngx_cpu_pause();
        }
    }

    assert(*lock == 1);
}

static void
spinlock_unlock(ngx_atomic_t *lock)
{
    *lock = 0;
    ngx_memory_barrier();
}

static int
ngx_zookeeper_connected(lua_State * L)
{
    if (lua_gettop(L))
    {
        return ngx_zookeeper_lua_error(L, "connected", "no arguments expected");
    }

    lua_pushboolean(L, zoo.handle && zoo.connected);

    return 1;
}

static result_t *
alloc_result()
{
    return ngx_calloc(sizeof(result_t), ngx_cycle->log);
}

static void
free_result(result_t *r)
{
    if (r->data)
    {
        ngx_free(r->data);
    }
    ngx_free(r);
}

static int
ngx_zookeeper_check_completition(lua_State * L)
{
    result_t *r;
    int rc = 3;

    if (lua_gettop(L) != 1)
    {
        return ngx_zookeeper_lua_error(L, "check_completition", "exactly one arguments expected");
    }

    r = CAST(luaL_checkinteger(L, 1), result_t*);

    spinlock_lock(&r->lock);

    if (!zoo.handle)
    {
        r->forgotten = 1;
        spinlock_unlock(&r->lock);
        return ngx_zookeeper_lua_error(L, "check_completition", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        r->forgotten = 1;
        spinlock_unlock(&r->lock);
        return ngx_zookeeper_lua_error(L, "check_completition", "not connected");
    }

    lua_pushboolean(L, r->completed);

    if (r->completed)
    {
        if (r->data)
        {
            r->completition_fn(L, r->data);
            lua_pushnil(L);
        }
        else if (!r->error)
        {
            lua_pushnil(L);
            lua_pushnil(L);
        }
        else
        {
            lua_pushnil(L);
            lua_pushlstring(L, r->error, strlen(r->error));
        }

        if (r->stat.pzxid)
        {
            lua_createtable(L, 0, 11);

            lua_pushliteral(L, "czxid");
            lua_pushinteger(L, (lua_Integer) r->stat.czxid);
            lua_rawset(L, -3);

            lua_pushliteral(L, "mzxid");
            lua_pushinteger(L, (lua_Integer) r->stat.mzxid);
            lua_rawset(L, -3);

            lua_pushliteral(L, "ctime");
            lua_pushinteger(L, (lua_Integer) r->stat.ctime);
            lua_rawset(L, -3);

            lua_pushliteral(L, "mtime");
            lua_pushinteger(L, (lua_Integer) r->stat.mtime);
            lua_rawset(L, -3);

            lua_pushliteral(L, "version");
            lua_pushinteger(L, (lua_Integer) r->stat.version);
            lua_rawset(L, -3);

            lua_pushliteral(L, "cversion");
            lua_pushinteger(L, (lua_Integer) r->stat.cversion);
            lua_rawset(L, -3);

            lua_pushliteral(L, "aversion");
            lua_pushinteger(L, (lua_Integer) r->stat.aversion);
            lua_rawset(L, -3);

            lua_pushliteral(L, "ephemeralOwner");
            lua_pushinteger(L, (lua_Integer) r->stat.ephemeralOwner);
            lua_rawset(L, -3);

            lua_pushliteral(L, "dataLength");
            lua_pushinteger(L, (lua_Integer) r->stat.dataLength);
            lua_rawset(L, -3);

            lua_pushliteral(L, "numChildren");
            lua_pushinteger(L, (lua_Integer) r->stat.numChildren);
            lua_rawset(L, -3);

            lua_pushliteral(L, "pzxid");
            lua_pushinteger(L, (lua_Integer) r->stat.pzxid);
            lua_rawset(L, -3);

            ++rc;
        }

        free_result(r);
        r = NULL;
    }
    else
    {
        lua_pushnil(L);
        lua_pushnil(L);
        spinlock_unlock(&r->lock);
    }

    return rc;
}

static int
ngx_zookeeper_forgot(lua_State * L)
{
    result_t *r = CAST(luaL_checkinteger(L, 1), result_t*);

    spinlock_lock(&r->lock);

    if (r->completed)
    {
        free_result(r);
    }
    else
    {
        r->forgotten = 1;
        spinlock_unlock(&r->lock);
    }

    return 0;
}

static int
ngx_zookeeper_timeout(lua_State * L)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zookeeper_conf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_zookeeper_lua_module);
    lua_pushinteger(L, CAST(zookeeper_conf->recv_timeout, lua_Integer));
    return 1;
}

//---------------------------------------------------------------------------------------------------------

static void
ngx_zookeeper_string_completition(lua_State * L, void *data)
{
    string_result_t *g_r = (string_result_t *) data;
    if (g_r && g_r->len && g_r->data[0] != 0)
    {
        lua_pushlstring(L, (const char *) g_r->data, g_r->len);
    }
    else
    {
        lua_pushnil(L);
    }
}

static void
ngx_zookeeper_string_ready(int rc, const char *value, int value_len, const struct Stat *stat, const void *data)
{
    result_t *r = (result_t *) data;
    string_result_t *g_r;

    if (!r)
    {
        if (rc != ZOK)
        {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "Zookeeper error: %s", rc_str_s(rc));
        }
        return;
    }

    spinlock_lock(&r->lock);

    if (r->forgotten)
    {
        spinlock_unlock(&r->lock);
        free_result(r);
        return;
    }

    if (rc != ZOK)
    {
        r->error = rc_str_s(rc);
        goto end;
    }

    g_r = ngx_calloc(sizeof(string_result_t), ngx_cycle->log);
    if (!g_r)
    {
        goto error_alloc;
    }

    if (value && value_len)
    {
        g_r->data = ngx_calloc(value_len, ngx_cycle->log);
        if (!g_r->data)
        {
            ngx_free(g_r);
            goto error_alloc;
        }
 
        memcpy(g_r->data, value, value_len);     
        g_r->len = value_len;
    }

    r->data = g_r;

    if (stat)
    {
        memcpy(&r->stat, stat, sizeof(struct Stat));
    }

    goto end;

error_alloc:

    r->error = "Failed to allocate memory";

end:

    r->completed = 1;

    spinlock_unlock(&r->lock);
}

static void
ngx_zookeeper_void_completition(lua_State * L, void *data)
{}

static void
ngx_zookeeper_void_ready(int rc, const void *data)
{
    result_t *r = (result_t *) data;

    if (r == NULL)
    {
        return;
    }

    spinlock_lock(&r->lock);

    if (r->forgotten)
    {
        spinlock_unlock(&r->lock);
        free_result(r);
        return;
    }

    if (rc != ZOK)
    {
        r->error = rc_str_s(rc);
    }

    r->completed = 1;

    spinlock_unlock(&r->lock);
}

//---------------------------------------------------------------------------------------------------------

static void
ngx_zookeeper_get_completition(lua_State * L, void *data)
{
    ngx_zookeeper_string_completition(L, data);
}

static void
ngx_zookeeper_get_ready(int rc, const char *value, int value_len, const struct Stat *stat, const void *data)
{
    ngx_zookeeper_string_ready(rc ,value, value_len, stat, data);
}

static int
ngx_zookeeper_aget(lua_State * L)
{
    int rc;
    str_t path;
    result_t *r;

    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "aget", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "aget", "not connected");
    }

    if (lua_gettop(L) != 1)
    {
        return ngx_zookeeper_lua_error(L, "aget", "exactly one arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "aget", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);
    r->completition_fn = ngx_zookeeper_get_completition;

    rc = zoo_aget(zoo.handle, path.data, 0, ngx_zookeeper_get_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "aget", rc_str_s(rc));
    }

    lua_pushinteger(L, CAST(r, lua_Integer));
    lua_pushnil(L);

    return 2;
}

//---------------------------------------------------------------------------------------------

static void
ngx_zookeeper_get_childrens_completition(lua_State * L, void *data)
{
    get_childs_result_t *g_r = (get_childs_result_t *) data;
    int j;

    if (!g_r || !g_r->array)
    {
        lua_pushnil(L);
        return;
    }

    lua_createtable(L, g_r->count, 0);

    for (j = 0; j < g_r->count; ++j)
    {
        lua_pushlstring(L, (char *) g_r->array[j].data, g_r->array[j].len);
        lua_rawseti (L, -2, j + 1);
    }
}

static void
ngx_zookeeper_get_childrens_ready(int rc, const struct String_vector *strings, const void *data)
{
    result_t *r = (result_t *) data;
    get_childs_result_t *g_r;

    spinlock_lock(&r->lock);

    if (r->forgotten)
    {
        spinlock_unlock(&r->lock);
        free_result(r);
        return;
    }

    if (rc != ZOK)
    {
        r->error = rc_str_s(rc);
        goto end;
    }
    
    g_r = ngx_calloc(sizeof(get_childs_result_t), ngx_cycle->log);
    if (!g_r)
    {
        goto error_alloc;
    }

    if (strings && strings->data && strings->count)
    {
        g_r->array = ngx_calloc(sizeof(ngx_str_t) * strings->count, ngx_cycle->log);
        if (!g_r->array)
        {
            ngx_free(g_r);
            goto error_alloc;
        }

        for (g_r->count = 0; g_r->count < strings->count; ++g_r->count)
        {
            int len = strlen(strings->data[g_r->count]);

            g_r->array[g_r->count].data = ngx_calloc(len, ngx_cycle->log);
            if (!g_r->array[g_r->count].data)
            {
                goto clean;
            }

            g_r->array[g_r->count].len = len;                    
            memcpy(g_r->array[g_r->count].data, strings->data[g_r->count], len);
        }
    }

    r->data = g_r;

    goto end;

error_alloc:

    r->error = "Failed to allocate memory";

end:

    r->completed = 1;

    spinlock_unlock(&r->lock);

    return;

clean:

    if (g_r && g_r->array)
    {
        int j;
        for (j = 0; j < g_r->count; ++j)
        {
            if (g_r->array[j].data)
            {
                ngx_free(g_r->array[j].data);
            }
        }

        ngx_free(g_r->array);
        ngx_free(g_r);
    }

    goto error_alloc;
}

static int
ngx_zookeeper_aget_childrens(lua_State * L)
{
    int rc;
    str_t path;
    result_t *r;

    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "aget_childrens", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "aget_childrens", "not connected");
    }

    if (lua_gettop(L) != 1)
    {
        return ngx_zookeeper_lua_error(L, "aget_childrens", "exactly one arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "aget_childrens", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);
    r->completition_fn = ngx_zookeeper_get_childrens_completition;

    rc = zoo_aget_children(zoo.handle, path.data, 0, ngx_zookeeper_get_childrens_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "aget_childrens", rc_str_s(rc));
    }

    lua_pushinteger(L, CAST(r, lua_Integer));
    lua_pushnil(L);

    return 2;
}

//---------------------------------------------------------------------------------------------

static void
ngx_zookeeper_set_completition(lua_State * L, void *data)
{
    ngx_zookeeper_void_completition(L, data);
}

static void
ngx_zookeeper_set_ready(int rc, const struct Stat *stat, const void *data)
{
    result_t *r = (result_t *) data;

    ngx_zookeeper_void_ready(rc, data);

    if (rc == ZOK && stat)
    {
        memcpy(&r->stat, stat, sizeof(struct Stat));
    }
}

static int
ngx_zookeeper_aset(lua_State * L)
{
    int rc;
    lua_Integer version = -1;
    str_t path, value;
    result_t *r;

    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "aset", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "aset", "not connected");
    }

    rc = lua_gettop(L); 

    if (rc != 2 && rc != 3)
    {
        return ngx_zookeeper_lua_error(L, "aset", "exactly 2 or 3 arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "aset", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);
    value.data = luaL_checklstring(L, 2, &value.len);

    if (rc == 3)
    {
        version = luaL_checkinteger(L, 3);
    }

    r->completition_fn = ngx_zookeeper_set_completition;

    rc = zoo_aset(zoo.handle, path.data, value.data, value.len, version, ngx_zookeeper_set_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "aset", rc_str_s(rc));
    }

    lua_pushinteger(L, CAST(r, lua_Integer));
    lua_pushnil(L);

    return 2;
}

//---------------------------------------------------------------------------------------------

static void
ngx_zookeeper_create_completition(lua_State * L, void *data)
{
    ngx_zookeeper_string_completition(L, data);
}

static void
ngx_zookeeper_create_ready(int rc, const char *value, const void *data)
{
    ngx_zookeeper_string_ready(rc, value, value ? strlen(value) : 0, NULL, data);
}

static int
ngx_zookeeper_acreate(lua_State * L)
{
    int rc, flags = 0;
    str_t path, value;
    result_t *r;

    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "not connected");
    }

    if (lua_gettop(L) != 2 && lua_gettop(L) != 3)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "exactly 2 or 3 arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);
    value.data = luaL_checklstring(L, 2, &value.len);

    r->completition_fn = ngx_zookeeper_create_completition;

    if (lua_gettop(L) == 3)
    {
        flags = luaL_checkinteger(L, 3);
    }

    rc = zoo_acreate(zoo.handle, path.data, value.data, value.len, &ZOO_OPEN_ACL_UNSAFE, flags, ngx_zookeeper_create_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "acreate", rc_str_s(rc));
    }

    lua_pushinteger(L, CAST(r, lua_Integer));
    lua_pushnil(L);

    return 2;
}

//---------------------------------------------------------------------------------------------

static void
ngx_zookeeper_delete_completition(lua_State * L, void *data)
{
    ngx_zookeeper_void_completition(L, data);
}

static void
ngx_zookeeper_delete_ready(int rc, const void *data)
{
    return ngx_zookeeper_void_ready(rc, data);
}

static int
ngx_zookeeper_adelete(lua_State * L)
{
    int rc;
    str_t path;
    result_t *r;

    if (!zoo.handle)
    {
        return ngx_zookeeper_lua_error(L, "adelete", "zookeeper handle is nil");
    }

    if (!zoo.connected)
    {
        return ngx_zookeeper_lua_error(L, "adelete", "not connected");
    }

    if (lua_gettop(L) != 1)
    {
        return ngx_zookeeper_lua_error(L, "adelete", "exactly one arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "adelete", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);

    r->completition_fn = ngx_zookeeper_delete_completition;

    rc = zoo_adelete(zoo.handle, path.data, -1, ngx_zookeeper_delete_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "adelete", rc_str_s(rc));
    }

    lua_pushinteger(L, CAST(r, lua_Integer));
    lua_pushnil(L);

    return 2;
}
