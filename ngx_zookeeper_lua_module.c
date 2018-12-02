#include <ngx_core.h>

#include <ngx_http.h>
#include <lauxlib.h>
#include <assert.h>
#include <zookeeper/zookeeper.h>
#include <ngx_inet.h>


#include "ngx_http_lua_api.h"


ngx_module_t ngx_zookeeper_lua_module;


static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf);


static char *
ngx_http_zookeeper_lua_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_int_t
ngx_zookeeper_lua_init(ngx_conf_t *cf);


static int
ngx_zookeeper_lua_create_module(lua_State *L);


ngx_int_t
ngx_zookeeper_lua_init_worker(ngx_cycle_t *cycle);


void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle);

static char *
ngx_http_zookeeper_lua_hosts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static char *
ngx_http_zookeeper_lua_log_level(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_recv_timeout(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_read_only(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_ethemeral_node(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_register_port(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


typedef struct
{
    ngx_addr_t   *addrs;
    ngx_uint_t    naddrs;
    ngx_str_t     hosts;
    ngx_int_t     recv_timeout;
    int           init_flags;
    ngx_array_t  *nodes;
    ZooLogLevel   log_level;
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
      NGX_CONF_TAKE2|NGX_CONF_TAKE3,
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


static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf;
    ngx_url_t                                   u;
    ngx_uint_t                                  j;

    zmcf = ngx_pcalloc(cf->pool,
        sizeof(ngx_http_zookeeper_lua_module_main_conf_t));
    if (zmcf == NULL)
        return NULL;

    zmcf->log_level = ZOO_LOG_LEVEL_ERROR;
    zmcf->recv_timeout = 10000;
    zmcf->init_flags = 0;
    zmcf->nodes = ngx_array_create(cf->pool, 1000, sizeof(ethemeral_node_t));

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = cf->cycle->hostname;
    u.default_port = 1;

    if (ngx_parse_url(cf->pool, &u) == NGX_OK) {

        zmcf->addrs = u.addrs;
        zmcf->naddrs = u.naddrs;

        for (j = 0; j < u.naddrs; j++)
            zmcf->addrs[j].name.len -= 2;
    }

    return zmcf;
}


static char *
ngx_http_zookeeper_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_lua_hosts(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf = conf;
    ngx_str_t                                  *values = cf->args->elts;

    zmcf->hosts.data = ngx_pcalloc(cf->pool, values[1].len + 1);
    if (zmcf->hosts.data == NULL)
        return NULL;

    ngx_memcpy(zmcf->hosts.data, values[1].data, values[1].len);
    zmcf->hosts.len = values[1].len;

    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_lua_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zmcf = conf;
    ngx_str_t *values = cf->args->elts;

    if (ngx_strncasecmp((u_char*) "error", values[1].data, 5) == 0)
        zmcf->log_level = ZOO_LOG_LEVEL_ERROR;
    else if (ngx_strncasecmp((u_char*) "warn", values[1].data, 4) == 0)
        zmcf->log_level = ZOO_LOG_LEVEL_WARN;
    else if (ngx_strncasecmp((u_char*) "info", values[1].data, 4) == 0)
        zmcf->log_level = ZOO_LOG_LEVEL_INFO;
    else if (ngx_strncasecmp((u_char*) "debug", values[1].data, 5) == 0)
        zmcf->log_level = ZOO_LOG_LEVEL_DEBUG;
    else
        return "invalid zookeeper_log_level value (error, warn, info, debug)";

    zoo_set_debug_level(zmcf->log_level);

    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_lua_recv_timeout(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t *zmcf = conf;
    ngx_str_t *values = cf->args->elts;

    zmcf->recv_timeout = ngx_atoi(values[1].data, values[1].len);

    if (zmcf->recv_timeout == (ngx_int_t) NGX_ERROR
        || zmcf->recv_timeout < 1
        || zmcf->recv_timeout > 60000)
        return "invalid value (1-60000 milliseconds)";

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
ngx_http_zookeeper_lua_ethemeral_node(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf = conf;
    ngx_str_t                                  *values = cf->args->elts;
    ethemeral_node_t                           *node;
    char                                       *s;
    ngx_str_t                                  *subpath;

    node = ngx_array_push(zmcf->nodes);

    node->path = ngx_array_create(cf->pool, 1000, sizeof(ngx_str_t));

    for (s = ngx_strchr(values[1].data + 1, '/');
         s;
         s = ngx_strchr(s + 1, '/'))
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
        return NULL;

    ngx_snprintf(node->instance.data, node->instance.len + 1, "%s/%s",
                 values[1].data, node->value.data);

    node->epoch = 0;

    if (cf->args->nelts == 4) {

        node->data.len = values[3].len;
        node->data.data = ngx_pcalloc(cf->pool, node->data.len + 1);

        if (node->data.data == NULL)
            return NULL;

        ngx_memcpy(node->data.data, values[3].data, node->data.len);

    } else {

        node->data.data = (u_char *) "";
        node->data.len = 0;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_lua_register_port(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf = conf;
    ngx_str_t                                  *values = cf->args->elts;
    ethemeral_node_t                           *node;
    char                                       *s;
    ngx_str_t                                  *subpath;
    ngx_uint_t                                  j;

    for (j = 0; j < zmcf->naddrs; j++) {
        node = ngx_array_push(zmcf->nodes);

        node->path = ngx_array_create(cf->pool, 1000, sizeof(ngx_str_t));

        for (s = ngx_strchr(values[1].data + 1, '/');
             s;
             s = ngx_strchr(s + 1, '/'))
        {
            subpath = ngx_array_push(node->path);
            subpath->len = (u_char *)s - values[1].data;
            subpath->data = ngx_pcalloc(cf->pool, subpath->len + 1);
            ngx_memcpy(subpath->data, values[1].data, subpath->len);
        }

        subpath = ngx_array_push(node->path);
        subpath->data = values[1].data;
        subpath->len = values[1].len;

        node->value.len = zmcf->addrs[j].name.len + values[2].len + 1;
        node->value.data = ngx_pcalloc(cf->pool, node->value.len + 1);
        ngx_snprintf(node->value.data, node->value.len, "%V:%s",
                     &zmcf->addrs[j].name, values[2].data);

        node->instance.len = values[1].len + node->value.len + 1;
        node->instance.data = ngx_pcalloc(cf->pool, node->instance.len + 1);
        if (node->instance.data == NULL)
            return NULL;

        ngx_snprintf(node->instance.data, node->instance.len + 1, "%s/%s",
                     values[1].data, node->value.data);

        node->epoch = 0;

        if (cf->args->nelts == 4) {

            node->data.len = values[3].len;
            node->data.data = ngx_pcalloc(cf->pool, node->data.len + 1);

            if (node->data.data == NULL)
                return NULL;

            ngx_memcpy(node->data.data, values[3].data, node->data.len);

        } else {

            node->data.data = (u_char *) "";
            node->data.len = 0;
        }
    }

    return NGX_CONF_OK;
}


typedef struct
{
    zhandle_t        *handle;
    ngx_flag_t        connected;
    const clientid_t *client_id;
    ngx_flag_t        expired;
    int               epoch;
} zookeeper_t;


static zookeeper_t zoo = {
    .handle    = NULL,
    .connected = 0,
    .client_id = NULL,
    .expired   = 1,
    .epoch     = 1
};


ngx_int_t
ngx_zookeeper_lua_init(ngx_conf_t *cf)
{
    if (ngx_http_lua_add_package_preload(cf, "ngx.zookeeper",
                                         ngx_zookeeper_lua_create_module)
        != NGX_OK)
        return NGX_ERROR;

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
ngx_zerr(int rc)
{
    if (rc == ZOK)
        return "OK";
    if (rc == ZSYSTEMERROR)
        return "System error";
    if (rc == ZRUNTIMEINCONSISTENCY)
        return "Runtime inconsistency";
    if (rc == ZDATAINCONSISTENCY)
        return "Data inconsistency";
    if (rc == ZCONNECTIONLOSS)
        return "Connection to the server has been lost";
    if (rc == ZMARSHALLINGERROR)
        return "Error while marshalling or unmarshalling data ";
    if (rc == ZUNIMPLEMENTED)
        return "Operation not implemented";
    if (rc == ZOPERATIONTIMEOUT)
        return "Operation timeout";
    if (rc == ZBADARGUMENTS)
        return "Invalid argument";
    if (rc == ZINVALIDSTATE)
        return "Invalid zhandle state";
    if (rc == ZAPIERROR)
        return "API error";
    if (rc == ZNONODE)
        return "Znode does not exist";
    if (rc == ZNOAUTH)
        return "Not authenticated";
    if (rc == ZBADVERSION)
        return "Version conflict";
    if (rc == ZNOCHILDRENFOREPHEMERALS)
        return "Ephemeral nodes may not have children";
    if (rc == ZNODEEXISTS)
        return "Znode already exists";
    if (rc == ZNOTEMPTY)
        return "The znode has children";
    if (rc == ZSESSIONEXPIRED)
        return "The session has been expired by the server";
    if (rc == ZINVALIDCALLBACK)
        return "Invalid callback specified";
    if (rc == ZINVALIDACL)
        return "Invalid ACL specified";
    if (rc == ZAUTHFAILED)
        return "Client authentication failed";
    if (rc == ZCLOSING)
        return "ZooKeeper session is closing";
    if (rc == ZNOTHING)
        return "No response from server";
    if (rc == ZSESSIONMOVED)
        return "Session moved to a different server";
    return "UNKNOWN_EVENT_TYPE";
}


static void
ngx_zookeeper_register_ready(int rc, const char *value, const void *data)
{
    ethemeral_node_t *node = (ethemeral_node_t *) data;

    if (rc != ZOK) {
        if (rc != ZNODEEXISTS) {
            if (data) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "Zookeeper can't register ephemeral node %s : %s",
                              node->instance.data, ngx_zerr(rc));
            } else {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "Zookeeper can't create node : %s", ngx_zerr(rc));
            }
        }
        return;
    }

    if (data) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "Nginx has been registered, instance: %s",
                      node->instance.data);

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
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf;
    ethemeral_node_t                           *nodes;
    int                                         rc;
    ngx_uint_t                                  i, j;
    ngx_str_t                                  *path;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);
    nodes = (ethemeral_node_t *)zmcf->nodes->elts;

    if (zoo.expired) {

        if (zoo.handle != NULL) {

            zookeeper_close(zoo.handle);
            zoo.handle = NULL;
            zoo.client_id = 0;
        }

        initialize(ngx_cycle);
    }

    if (zmcf->nodes->nelts == 0)
        goto settimer;

    if (!zoo.connected)
        goto settimer;

    for (i = 0; i < zmcf->nodes->nelts; i++) {

        if (zoo.epoch > nodes[i].epoch) {

            zoo_adelete(zoo.handle, (const char *)nodes[i].instance.data, -1,
                        ngx_zookeeper_delete_ready, NULL);

            path = (ngx_str_t *)nodes[i].path->elts;

            for (j = 0; j < nodes[i].path->nelts; ++j) {
                rc = zoo_acreate(zoo.handle, (const char *) path[j].data, "", 0,
                    &ZOO_OPEN_ACL_UNSAFE, 0, ngx_zookeeper_register_ready,
                    NULL);

                if (rc != ZOK)
                    ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                                  "Zookeeper: error create node %s : %s",
                                  path[j].data, ngx_zerr(rc));
            }

            rc = zoo_acreate(zoo.handle, (const char *) nodes[i].instance.data,
                (const char *)nodes[i].data.data, nodes[i].data.len,
                &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL,
                ngx_zookeeper_register_ready, &nodes[i]);

            if (rc != ZOK)
                ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                              "Zookeeper: error register instance: %s",
                              ngx_zerr(rc));
        }
    }

settimer:

    if (ngx_exiting || ngx_terminate || ngx_quit)
        // cleanup
        ngx_memset(ev, 0, sizeof(ngx_event_t));
    else
        ngx_add_timer(ev, zmcf->recv_timeout * 2);
}


static void
ngx_zookeeper_create_ready(int rc, const char *value, const void *p);


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
    ngx_http_zookeeper_lua_module_main_conf_t *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    zoo.handle = zookeeper_init2((const char *) zmcf->hosts.data,
                                 session_watcher,
                                 zmcf->recv_timeout,
                                 zoo.client_id,
                                 0,
                                 zmcf->init_flags,
                                 ngx_log_message);

    if (zoo.handle == NULL) {

        u_char err[1024];

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "Zookeeper: error create zookeeper handle: %s",
                      ngx_strerror(errno, err, sizeof(err)));

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
    if (type == ZOO_SESSION_EVENT) {

        if (state == ZOO_CONNECTED_STATE) {

            zoo.connected = 1;
            zoo.epoch = zoo.epoch + 1;
            zoo.client_id = zoo_client_id(zh);

            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "Zookeeper: received a connected event");

        } else if (state == ZOO_CONNECTING_STATE) {

            if (zoo.connected) {
                ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                              "Zookeeper: disconnected");
            }

            zoo.connected = 0;

        } else if (state == ZOO_EXPIRED_SESSION_STATE) {

            if (zh != NULL) {

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
    ngx_http_zookeeper_lua_module_main_conf_t *zmcf;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    zmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    if (zmcf == NULL || zmcf->hosts.len == 0)
        return NGX_OK;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been initialized in %s mode",
                  zmcf->init_flags == ZOO_READONLY ? "ro" : "rw");

    initialize(cycle);

    if (ngx_worker != 0)
        return NGX_OK;

    register_ev.log = cycle->log;

    ngx_add_timer(&register_ev, 2000);

    return NGX_OK;
}


void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle)
{
    int rc;

    if (register_ev.log != NULL) {
        ngx_del_timer(&register_ev);
        ngx_memset(&register_ev, 0, sizeof(ngx_event_t));
    }

    if (zoo.handle == NULL)
        return;

    rc = zookeeper_close(zoo.handle);
    if (rc != ZOK) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "Zookeeper close connection error: %s", ngx_zerr(rc));
    }

    zoo.handle = NULL;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been destroyed");
}


static int ngx_zookeeper_connected(lua_State *L);

static int ngx_zookeeper_aget(lua_State *L);

static int ngx_zookeeper_aset(lua_State *L);

static int ngx_zookeeper_aget_childrens(lua_State *L);

static int ngx_zookeeper_acreate(lua_State *L);

static int ngx_zookeeper_adelete(lua_State *L);

static int ngx_zookeeper_check_completition(lua_State *L);

static int ngx_zookeeper_timeout(lua_State *L);

static int ngx_zookeeper_addrs(lua_State *L);

static int ngx_zookeeper_hostname(lua_State *L);


#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM < 502

static void
luaL_setfuncs(lua_State *l, const luaL_Reg *reg, int nup)
{
    int i;

    luaL_checkstack(l, nup, "too many upvalues");
    for (; reg->name != NULL; reg++) {
        for (i = 0; i < nup; i++) {
            lua_pushvalue(l, -nup);
        }
        lua_pushcclosure(l, reg->func, nup);
        lua_setfield(l, -(nup + 2), reg->name);
    }
    lua_pop(l, nup);
}

#endif


static int
delete(lua_State *L);


static void
ngx_zookeeper_register_gc(lua_State *L)
{
    luaL_Reg regZoo[] =
    {
        { "__gc", delete },
        { NULL, NULL }
    };

    luaL_newmetatable(L, "ngx_zoo");
    luaL_setfuncs(L, regZoo, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -1, "__index");

    lua_pop(L, 1);
}


static int
ngx_zookeeper_lua_create_module(lua_State *L)
{
    ngx_zookeeper_register_gc(L);

    lua_createtable(L, 0, 10);

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

    lua_pushcfunction(L, ngx_zookeeper_addrs);
    lua_setfield(L, -2, "addrs");

    lua_pushcfunction(L, ngx_zookeeper_hostname);
    lua_setfield(L, -2, "hostname");

    return 1;
}


static int
ngx_zookeeper_lua_error(lua_State *L, const char *where, const char *error)
{
    char tmp[1024];

    snprintf(tmp, 1023, "%s: %s", where, error);

    lua_pushnil(L);
    lua_pushlstring(L, tmp, strlen(tmp));

    return 2;
}


typedef struct
{
    char        *data;
    ngx_uint_t   len;
} str_t;


typedef void (*completition_t)(lua_State *L, void *p);


typedef struct
{
    ngx_flag_t       completed;
    completition_t   completition_fn;

    struct Stat      stat;
    void            *data;
    const char      *error;

    ngx_atomic_t               lock;
    volatile ngx_atomic_int_t  refs;
    ngx_pool_t                *pool;
} datatype_t;


static void
dereference(datatype_t *data, ngx_atomic_int_t n)
{
    if (data->pool && ngx_atomic_fetch_add(&data->refs, -n) <= n) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "zoo: free %xd", data);

        ngx_destroy_pool(data->pool);

        data->pool = NULL;
    }
}


static int
delete(lua_State *L)
{
    dereference(luaL_checkudata(L, 1, "ngx_zoo"), 2);
    return 0;
}


static datatype_t *
new(lua_State *L)
{
    datatype_t  *data;
    ngx_pool_t  *pool;

    data = (datatype_t *) lua_newuserdata(L, sizeof(datatype_t));
    if (data == NULL)
        return NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "zoo: new %xd", data);

    ngx_memzero(data, sizeof(datatype_t));

    pool = ngx_create_pool(2048, ngx_cycle->log);
    if (pool == NULL)
        return NULL;

    data->refs = 2;
    data->pool = pool;

    luaL_getmetatable(L, "ngx_zoo");
    lua_setmetatable(L, -2);

    return data;
}


static int
ngx_zookeeper_connected(lua_State *L)
{
    if (lua_gettop(L))
        return ngx_zookeeper_lua_error(L, "connected", "no arguments expected");

    lua_pushboolean(L, zoo.handle && zoo.connected);

    return 1;
}


static int
ngx_zookeeper_check_completition(lua_State *L)
{
    datatype_t  *data;

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "exactly one arguments expected");

    if (!lua_isuserdata(L, 1))
        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "argument must be a userdata");

    data = (datatype_t *) luaL_checkudata(L, 1, "ngx_zoo");
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "check_completition",
                                      "argument is not a zookeeper type");

    ngx_rwlock_wlock(&data->lock);

    if (zoo.handle == NULL) {

        ngx_rwlock_unlock(&data->lock);

        dereference(data, 1);

        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "zookeeper handle is nil");
    }

    if (!zoo.connected) {

        ngx_rwlock_unlock(&data->lock);

        dereference(data, 1);

        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "not connected");
    }

    lua_pushboolean(L, data->completed);

    if (!data->completed) {

        ngx_rwlock_unlock(&data->lock);
        return 1;
    }

    if (data->data) {

        data->completition_fn(L, data->data);
        lua_pushnil(L);

    } else if (data->error == NULL) {

        lua_pushnil(L);
        lua_pushnil(L);

    } else {

        lua_pushnil(L);
        lua_pushlstring(L, data->error, strlen(data->error));
    }

    if (data->stat.pzxid) {

        lua_createtable(L, 0, 11);

        lua_pushliteral(L, "czxid");
        lua_pushinteger(L, data->stat.czxid);
        lua_rawset(L, -3);

        lua_pushliteral(L, "mzxid");
        lua_pushinteger(L, data->stat.mzxid);
        lua_rawset(L, -3);

        lua_pushliteral(L, "ctime");
        lua_pushinteger(L, data->stat.ctime);
        lua_rawset(L, -3);

        lua_pushliteral(L, "mtime");
        lua_pushinteger(L, data->stat.mtime);
        lua_rawset(L, -3);

        lua_pushliteral(L, "version");
        lua_pushinteger(L, data->stat.version);
        lua_rawset(L, -3);

        lua_pushliteral(L, "cversion");
        lua_pushinteger(L, data->stat.cversion);
        lua_rawset(L, -3);

        lua_pushliteral(L, "aversion");
        lua_pushinteger(L, data->stat.aversion);
        lua_rawset(L, -3);

        lua_pushliteral(L, "ephemeralOwner");
        lua_pushinteger(L, data->stat.ephemeralOwner);
        lua_rawset(L, -3);

        lua_pushliteral(L, "dataLength");
        lua_pushinteger(L, data->stat.dataLength);
        lua_rawset(L, -3);

        lua_pushliteral(L, "numChildren");
        lua_pushinteger(L, data->stat.numChildren);
        lua_rawset(L, -3);

        lua_pushliteral(L, "pzxid");
        lua_pushinteger(L, data->stat.pzxid);
        lua_rawset(L, -3);
    }

    dereference(data, 1);

    return 3 + (data->stat.pzxid ? 1 : 0);
}


static int
ngx_zookeeper_timeout(lua_State *L)
{
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_zookeeper_lua_module);

    lua_pushinteger(L, zmcf->recv_timeout);

    return 1;
}


static int
ngx_zookeeper_addrs(lua_State *L)
{
    ngx_http_zookeeper_lua_module_main_conf_t  *zmcf;
    ngx_uint_t                                  j;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_zookeeper_lua_module);

    lua_newtable(L);

    for (j = 0; j < zmcf->naddrs; j++) {

        lua_pushlstring(L, (const char *) zmcf->addrs[j].name.data,
                        zmcf->addrs[j].name.len);
        lua_rawseti(L, -2, j + 1);
    }

    return 1;
}


static int
ngx_zookeeper_hostname(lua_State *L)
{
    lua_pushlstring(L, (const char *) ngx_cycle->hostname.data,
                    ngx_cycle->hostname.len);
    return 1;
}


//------------------------------------------------------------------------------


static void
ngx_zookeeper_string_completition(lua_State *L, void *p)
{
    str_t  *s = p;
    return lua_pushlstring(L, s->data, s->len);
}


static void
ngx_zookeeper_string_ready(int rc, const char *value, int value_len,
    const struct Stat *stat, const void *p)
{
    datatype_t  *data = (datatype_t *) p;
    str_t       *s;

    if (data == NULL)
        return;

    ngx_rwlock_wlock(&data->lock);

    if (rc != ZOK) {

        data->error = ngx_zerr(rc);
        goto end;
    }

    s = ngx_pcalloc(data->pool, sizeof(str_t));
    if (s == NULL)
        goto nomem;

    if (value != NULL && value_len != 0) {

        s->data = ngx_pcalloc(data->pool, value_len);
        if (s->data == NULL)
            goto nomem;
 
        ngx_memcpy(s->data, value, value_len);
        s->len = value_len;
    } else {

        s->data = "";
        s->len = 0;
    }

    data->data = s;

    if (stat)
        ngx_memcpy(&data->stat, stat, sizeof(struct Stat));

    goto end;

nomem:

    data->error = "Failed to allocate memory";

end:

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

    dereference(data, 1);
}


static void
ngx_zookeeper_void_completition(lua_State *L, void *p)
{}


static void
ngx_zookeeper_void_ready(int rc, const void *p)
{
    datatype_t  *data = (datatype_t *) p;

    if (data == NULL)
        return;

    ngx_rwlock_wlock(&data->lock);

    if (rc != ZOK)
        data->error = ngx_zerr(rc);

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

    dereference(data, 1);
}

//------------------------------------------------------------------------------

static void
ngx_zookeeper_get_completition(lua_State *L, void *p)
{
    ngx_zookeeper_string_completition(L, p);
}


static void
ngx_zookeeper_get_ready(int rc, const char *value, int value_len,
    const struct Stat *stat, const void *p)
{
    ngx_zookeeper_string_ready(rc, value, value_len, stat, p);
}


static int
ngx_zookeeper_aget(lua_State *L)
{
    int          rc;
    str_t        path;
    datatype_t  *data;

    if (zoo.handle == NULL)
        return ngx_zookeeper_lua_error(L, "aget", "zookeeper handle is nil");

    if (!zoo.connected)
        return ngx_zookeeper_lua_error(L, "aget", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "aget",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "aget", "Failed to allocate memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    data->completition_fn = ngx_zookeeper_get_completition;

    rc = zoo_aget(zoo.handle, path.data, 0, ngx_zookeeper_get_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data, 2);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "aget", ngx_zerr(rc));
}


//------------------------------------------------------------------------------

static void
ngx_zookeeper_get_childrens_completition(lua_State *L, void *p)
{
    ngx_array_t  *data = p;
    str_t        *s;
    ngx_uint_t    j;

    lua_createtable(L, data->nelts, 0);

    s = data->elts;

    for (j = 0; j < data->nelts; j++) {

        lua_pushlstring(L, s[j].data, s[j].len);
        lua_rawseti(L, -2, j + 1);
    }
}


static void
ngx_zookeeper_get_childrens_ready(int rc, const struct String_vector *strings,
    const void *p)
{
    datatype_t   *data = (datatype_t *) p;
    ngx_array_t  *arr;
    str_t        *s;
    ngx_int_t     j;

    if (data == NULL)
        return;

    ngx_rwlock_wlock(&data->lock);

    if (rc != ZOK) {

        data->error = ngx_zerr(rc);
        goto end;
    }
    
    arr = ngx_array_create(data->pool, strings->count, sizeof(str_t));
    if (arr == NULL)
        goto nomem;

    if (strings != NULL && strings->data != NULL && strings->count != 0) {

        for (j = 0; j < strings->count; j++) {

            s = ngx_array_push(arr);
            if (s == NULL)
                goto nomem;

            s->len = strlen(strings->data[j]);
            s->data = ngx_pcalloc(data->pool, s->len);

            ngx_memcpy(s->data, strings->data[j], s->len);
        }
    }

    data->data = arr;
    
    goto end;

nomem:

    data->error = "Failed to allocate memory";

end:

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

    dereference(data, 1);
}


static int
ngx_zookeeper_aget_childrens(lua_State *L)
{
    int          rc;
    str_t        path;
    datatype_t  *data;

    if (zoo.handle == NULL)
        return ngx_zookeeper_lua_error(L, "aget_childrens",
                                       "zookeeper handle is nil");

    if (!zoo.connected)
        return ngx_zookeeper_lua_error(L, "aget_childrens", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "aget_childrens",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "aget_childrens",
                                       "Failed to allocate memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    data->completition_fn = ngx_zookeeper_get_childrens_completition;

    rc = zoo_aget_children(zoo.handle, path.data, 0,
        ngx_zookeeper_get_childrens_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data, 2);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "aget_childrens", ngx_zerr(rc));
}


//------------------------------------------------------------------------------


static void
ngx_zookeeper_set_completition(lua_State *L, void *p)
{
    ngx_zookeeper_void_completition(L, p);
}


static void
ngx_zookeeper_set_ready(int rc, const struct Stat *stat, const void *p)
{
    datatype_t *data = (datatype_t *) p;

    if (data == NULL)
        return;

    ngx_rwlock_wlock(&data->lock);

    if (rc == ZOK) {

        if (stat)
            ngx_memcpy(&data->stat, stat, sizeof(struct Stat));

    } else
        data->error = ngx_zerr(rc);

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

    dereference(data, 1);
}


static int
ngx_zookeeper_aset(lua_State *L)
{
    int          rc;
    lua_Integer  version = -1;
    str_t        path, value;
    datatype_t  *data;

    if (zoo.handle == NULL)
        return ngx_zookeeper_lua_error(L, "aset", "zookeeper handle is nil");

    if (!zoo.connected)
        return ngx_zookeeper_lua_error(L, "aset", "not connected");

    rc = lua_gettop(L); 

    if (rc != 2 && rc != 3)
        return ngx_zookeeper_lua_error(L, "aset",
            "exactly 2 or 3 arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "aset", "Failed to allocate memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    value.data = (char *) luaL_checklstring(L, 2, &value.len);

    if (rc == 3)
        version = luaL_checkinteger(L, 3);

    data->completition_fn = ngx_zookeeper_set_completition;

    rc = zoo_aset(zoo.handle, path.data, value.data, value.len, version,
                  ngx_zookeeper_set_ready, data);
    if (rc == ZOK) {
        return 1;
    }

    dereference(data, 2);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "aset", ngx_zerr(rc));
}


//------------------------------------------------------------------------------


static void
ngx_zookeeper_create_completition(lua_State *L, void *p)
{
    ngx_zookeeper_string_completition(L, p);
}


static void
ngx_zookeeper_create_ready(int rc, const char *value, const void *p)
{
    ngx_zookeeper_string_ready(rc, value, value ? strlen(value) : 0, NULL, p);
}


static int
ngx_zookeeper_acreate(lua_State *L)
{
    int rc, flags = 0;
    str_t path, value;
    datatype_t *data;

    if (zoo.handle == NULL) {
        return ngx_zookeeper_lua_error(L, "acreate", "zookeeper handle is nil");
    }

    if (!zoo.connected) {
        return ngx_zookeeper_lua_error(L, "acreate", "not connected");
    }

    if (lua_gettop(L) != 2 && lua_gettop(L) != 3) {
        return ngx_zookeeper_lua_error(L, "acreate",
                                       "exactly 2 or 3 arguments expected");
    }

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "acreate",
                                       "Failed to allocate memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    value.data = (char *) luaL_checklstring(L, 2, &value.len);

    data->completition_fn = ngx_zookeeper_create_completition;

    if (lua_gettop(L) == 3)
        flags = luaL_checkinteger(L, 3);

    rc = zoo_acreate(zoo.handle, path.data, value.data, value.len,
        &ZOO_OPEN_ACL_UNSAFE, flags, ngx_zookeeper_create_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data, 2);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "acreate", ngx_zerr(rc));
}


//------------------------------------------------------------------------------


static void
ngx_zookeeper_delete_completition(lua_State *L, void *p)
{
    ngx_zookeeper_void_completition(L, p);
}


static void
ngx_zookeeper_delete_ready(int rc, const void *p)
{
    return ngx_zookeeper_void_ready(rc, p);
}


static int
ngx_zookeeper_adelete(lua_State *L)
{
    int          rc;
    str_t        path;
    datatype_t  *data;

    if (zoo.handle == NULL)
        return ngx_zookeeper_lua_error(L, "adelete", "zookeeper handle is nil");

    if (!zoo.connected)
        return ngx_zookeeper_lua_error(L, "adelete", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "adelete",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "adelete",
                                       "Failed to allocate memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);

    data->completition_fn = ngx_zookeeper_delete_completition;

    rc = zoo_adelete(zoo.handle, path.data, -1,
                     ngx_zookeeper_delete_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data, 2);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "adelete", ngx_zerr(rc));
}
