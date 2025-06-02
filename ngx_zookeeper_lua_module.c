#include <ngx_core.h>

#include <ngx_http.h>
#include <lauxlib.h>
#include <luajit.h>
#include <assert.h>
#include <zookeeper/zookeeper.h>
#include <ngx_inet.h>


#include "ngx_http_lua_api.h"
#include "ngx_zookeeper_lua.h"


ngx_module_t ngx_zookeeper_lua_module;


static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf);


static ngx_int_t
ngx_zookeeper_lua_init(ngx_conf_t *cf);


static int
ngx_zookeeper_lua_create_module(lua_State *L);


ngx_int_t
ngx_zookeeper_lua_init_worker(ngx_cycle_t *cycle);


void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle);


static char *
ngx_http_zookeeper_lua_log_level(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_read_only(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_node(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_register_port(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_lua_register(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static char *
ngx_http_zookeeper_node_ephemeral(ngx_conf_t *cf, void *post, void *data);

static ngx_conf_num_bounds_t  ngx_http_zookeeper_check_inactive = {
    ngx_conf_check_num_bounds,
    0, NGX_MAX_INT_T_VALUE
};

static ngx_conf_num_bounds_t  ngx_http_zookeeper_check_timeout = {
    ngx_conf_check_num_bounds,
    1, 60000
};


static ngx_conf_post_t  ngx_http_zookeeper_ephemeral = {
    ngx_http_zookeeper_node_ephemeral
};


typedef struct
{
    zhandle_t           *handle;
    volatile ngx_int_t   connected;
    const clientid_t    *client_id;
    volatile ngx_flag_t  expired;
    volatile int         epoch;
    time_t               last_op;
} zookeeper_t;


typedef struct {
    ngx_str_t            path;
    int                  watch_type;
    volatile ngx_flag_t  changed;
} watched_t;

typedef struct
{
    ngx_addr_t   *addrs;
    ngx_uint_t    naddrs;
    ngx_str_t     hosts;
    ngx_int_t     recv_timeout;
    int           init_flags;
    ngx_array_t  *nodes;
    ZooLogLevel   log_level;
    ngx_int_t     inactive_time;

    zookeeper_t   zoo;
    ngx_event_t   ev;
    ngx_array_t  *watched;
    ngx_atomic_t  lock;
} ngx_http_zookeeper_lua_main_conf_t;


static ngx_command_t ngx_http_zookeeper_lua_commands[] = {

    { ngx_string("zookeeper"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zookeeper_lua_main_conf_t, hosts),
      NULL },

    { ngx_string("zookeeper_log_level"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_zookeeper_lua_log_level,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_recv_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zookeeper_lua_main_conf_t, recv_timeout),
      &ngx_http_zookeeper_check_timeout },

    { ngx_string("zookeeper_ethemeral_node"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
      NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_zookeeper_lua_node,
      0,
      0,
      &ngx_http_zookeeper_ephemeral },

    { ngx_string("zookeeper_ephemeral_node"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
      NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_zookeeper_lua_node,
      0,
      0,
      &ngx_http_zookeeper_ephemeral },

    { ngx_string("zookeeper_node"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|
      NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_zookeeper_lua_node,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_register_port"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
      ngx_http_zookeeper_lua_register_port,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_register"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
      ngx_http_zookeeper_lua_register,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_read_only"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_NOARGS,
      ngx_http_zookeeper_lua_read_only,
      0,
      0,
      NULL },

    { ngx_string("zookeeper_inactive_time"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_zookeeper_lua_main_conf_t, inactive_time),
      &ngx_http_zookeeper_check_inactive },

    ngx_null_command
};


static ngx_http_module_t ngx_zookeeper_lua_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_zookeeper_lua_init,                  /* postconfiguration */
    ngx_http_zookeeper_lua_create_main_conf, /* create main configuration */
    NULL,                                    /* init main configuration */
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


typedef struct {
    ngx_array_t  *path;
    char         *value;
    char         *node;
    char         *data;
    int           epoch;
    ngx_flag_t    ephemeral;
    const char   *fmt;
    const char   *update_fmt;
    ngx_flag_t    may_be_updated;
    ngx_int_t     timestamp;
} ngx_zoo_node_t;


static void
ngx_zookeeper_monitor(ngx_event_t *ev);


static void *
ngx_http_zookeeper_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    ngx_url_t                            u;
    ngx_uint_t                           j;
    ngx_connection_t                    *c;

    zmcf = ngx_pcalloc(cf->pool,
        sizeof(ngx_http_zookeeper_lua_main_conf_t));
    if (zmcf == NULL)
        return NULL;

    zmcf->log_level = ZOO_LOG_LEVEL_ERROR;
    zmcf->recv_timeout = NGX_CONF_UNSET;
    zmcf->inactive_time = NGX_CONF_UNSET;    
    zmcf->init_flags = 0;
    zmcf->nodes = ngx_array_create(cf->pool, 1000, sizeof(ngx_zoo_node_t));
    if (zmcf->nodes == NULL)
        return NULL;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = cf->cycle->hostname;
    u.default_port = 1;

    if (ngx_parse_url(cf->pool, &u) == NGX_OK) {

        zmcf->addrs = u.addrs;
        zmcf->naddrs = u.naddrs;

        for (j = 0; j < u.naddrs; j++)
            zmcf->addrs[j].name.len -= 2;
    }

    zmcf->zoo.expired = 1;
    zmcf->zoo.epoch = 1;
    zmcf->zoo.connected = NGX_DECLINED;

    zmcf->ev.handler = ngx_zookeeper_monitor;
    c = ngx_pcalloc(cf->pool, sizeof(ngx_connection_t));
    if (c == NULL)
        return NULL;
    c->fd = -1;
    zmcf->ev.data = c;

    zmcf->watched = ngx_array_create(cf->pool, 1000, sizeof(watched_t));
    if (zmcf->watched == NULL)
        return NULL;

    return zmcf;
}


static zookeeper_t *
ngx_http_zmcf()
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    return &zmcf->zoo;
}

static void
ngx_http_zookeeper_check_mon(void)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (!zmcf->ev.timer_set) {
        zmcf->zoo.last_op = ngx_time();
        ngx_zookeeper_monitor(&zmcf->ev);
    }
}


static ngx_flag_t
str_eq(ngx_str_t s1, ngx_str_t s2)
{
    return ngx_memn2cmp(s1.data, s2.data, s1.len, s2.len) == 0;
}


static char *
ngx_http_zookeeper_lua_log_level(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf = conf;
    ngx_str_t                            log_level;

    static const ngx_str_t LOG_ERR   = ngx_string("error");
    static const ngx_str_t LOG_INFO  = ngx_string("warn");
    static const ngx_str_t LOG_WARN  = ngx_string("info");
    static const ngx_str_t LOG_DEBUG = ngx_string("debug");

    log_level = ((ngx_str_t *) cf->args->elts)[1];
    ngx_strlow(log_level.data, log_level.data, log_level.len);

    if (str_eq(LOG_ERR, log_level))

        zmcf->log_level = ZOO_LOG_LEVEL_ERROR;
    else if (str_eq(LOG_WARN, log_level))

        zmcf->log_level = ZOO_LOG_LEVEL_WARN;
    else if (str_eq(LOG_INFO, log_level))

        zmcf->log_level = ZOO_LOG_LEVEL_INFO;
    else if (str_eq(LOG_DEBUG, log_level))

        zmcf->log_level = ZOO_LOG_LEVEL_DEBUG;
    else {

        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
            "invalid zookeeper_log_level value (error, warn, info, debug)");
        return NGX_CONF_ERROR;
    }

    zoo_set_debug_level(zmcf->log_level);

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


static ngx_array_t *
path_parse(ngx_pool_t *pool, ngx_str_t znode)
{
    ngx_array_t  *a;
    u_char       *s;
    u_char      **sub;

    a = ngx_array_create(pool, 20, sizeof(u_char *));
    if (a == NULL)
        return NULL;

    for (s = znode.data + 1;
         s <= znode.data + znode.len;
         s++) {

        if (s == znode.data + znode.len || *s == '/') {

            sub = ngx_array_push(a);
            if (sub == NULL)
                return NULL;

            *sub = ngx_pcalloc(pool, s - znode.data + 1);
            if (*sub == NULL)
                return NULL;

            ngx_memcpy(*sub, znode.data, s - znode.data);
        }
    }

    return a;
}


static char *
concat(ngx_pool_t *pool, ngx_str_t l, ngx_str_t r, char sep)
{
    u_char  *s;

    s = ngx_pcalloc(pool, l.len + r.len + 2);
    if (s == NULL)
        return NULL;

    ngx_snprintf(s, l.len + r.len + 2, "%V%c%V", &l, sep, &r);

    return (char *) s;
}


static char *
cstr(ngx_pool_t *pool, ngx_str_t s)
{
    u_char  *cs;

    cs = ngx_pcalloc(pool, s.len + 1);
    if (cs == NULL)
        return NULL;

    ngx_memcpy(cs, s.data, s.len);

    return (char *) cs;
}


static ngx_flag_t
exists_node(ngx_http_zookeeper_lua_main_conf_t *zmcf, const char *znode)
{
    ngx_uint_t       j;
    ngx_zoo_node_t  *nodes;

    nodes = zmcf->nodes->elts;

    for (j = 0; j < zmcf->nodes->nelts; j++)
        if (ngx_strcmp(znode, nodes[j].node) == 0)
            return 1;

    return 0;
}


static char *
ngx_http_zookeeper_lua_node(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf = conf;
    ngx_str_t                           *values = cf->args->elts;
    ngx_zoo_node_t                      *node;
    ngx_conf_post_t                     *post;

    node = ngx_array_push(zmcf->nodes);
    zmcf->nodes->nelts--;
    ngx_memzero(node, sizeof(ngx_zoo_node_t));

    node->path = path_parse(cf->pool, values[1]);
    node->value = cstr(cf->pool, values[2]);
    node->node = concat(cf->pool, values[1], values[2], '/');
    if (node->node == NULL)
        return NGX_CONF_ERROR;

    if (exists_node(zmcf, node->node))
        return NGX_CONF_OK;

    node->epoch = 0;
    node->ephemeral = 0;
    node->fmt = "Node has been created: %s = %s";
    node->update_fmt = "Node has been updated: %s = %s";
    node->may_be_updated = 1;

    if (cf->args->nelts == 4) {

        node->data = cstr(cf->pool, values[3]);
        if (node->data == NULL)
            return NGX_CONF_ERROR;

    } else
        node->data = "";

    zmcf->nodes->nelts++;

    if (cmd->post) {

        post = cmd->post;
        return post->post_handler(cf, post, node);
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_node_ephemeral(ngx_conf_t *cf, void *post, void *data)
{
    ngx_zoo_node_t  *node = data;

    node->ephemeral = 1;
    node->fmt = "Ephemeral node has been created: %s = %s";
    node->update_fmt = "Ephemeral node has been updated: %s = %s";
    node->may_be_updated = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_lua_register_port(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf = conf;
    ngx_str_t                           *values = cf->args->elts;
    ngx_zoo_node_t                      *node;
    ngx_str_t                            val;
    ngx_uint_t                           j;

    for (j = 0; j < zmcf->naddrs; j++) {

        node = ngx_array_push(zmcf->nodes);
        zmcf->nodes->nelts--;
        ngx_memzero(node, sizeof(ngx_zoo_node_t));

        node->path = path_parse(cf->pool, values[1]);
        node->value = concat(cf->pool, zmcf->addrs[j].name, values[2], ':');
        if (node->value == NULL)
            return NGX_CONF_ERROR;

        val.data = (u_char *) node->value;
        val.len = strlen(node->value);
        node->node = concat(cf->pool, values[1], val, '/');
        if (node->node == NULL)
            return NGX_CONF_ERROR;

        if (exists_node(zmcf, node->node))
            continue;

        node->epoch = 0;
        node->ephemeral = 1;
        node->fmt = "Nginx has been registered, instance: %s = %s";

        if (cf->args->nelts >= 4) {

            node->data = cstr(cf->pool, values[3]);
            if (node->data == NULL)
                return NGX_CONF_ERROR;

            if (cf->args->nelts == 5)
               node->timestamp = ngx_time() + ngx_max(0, ngx_atoi(values[4].data, values[4].len));
        } else
            node->data = "";

        zmcf->nodes->nelts++;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_zookeeper_lua_register(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf = conf;
    ngx_str_t                           *values = cf->args->elts;
    ngx_zoo_node_t                      *node;
    ngx_uint_t                           j;

    for (j = 0; j < zmcf->naddrs; j++) {

        node = ngx_array_push(zmcf->nodes);
        zmcf->nodes->nelts--;
        ngx_memzero(node, sizeof(ngx_zoo_node_t));

        node->path = path_parse(cf->pool, values[1]);
        node->value = cstr(cf->pool, zmcf->addrs[j].name);

        node->node = concat(cf->pool, values[1], zmcf->addrs[j].name, '/');
        if (node->node == NULL)
            return NGX_CONF_ERROR;

        if (exists_node(zmcf, node->node))
            continue;

        node->epoch = 0;
        node->ephemeral = 1;
        node->fmt = "Nginx has been registered, instance: %s = %s";

        if (cf->args->nelts >= 3) {

            node->data = cstr(cf->pool, values[2]);
            if (node->data == NULL)
                return NGX_CONF_ERROR;

            if (cf->args->nelts == 4)
                node->timestamp = ngx_time() + ngx_max(0, ngx_atoi(values[3].data, values[3].len));
        } else
            node->data = "";

        zmcf->nodes->nelts++;
    }

    return NGX_CONF_OK;
}


ngx_flag_t
ngx_zookeeper_lua_connected()
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    return zmcf->hosts.len != 0 /* not configured */ &&
        (!zmcf->ev.timer_set /* suspended */ || (zmcf->zoo.handle && zmcf->zoo.connected != NGX_ERROR));
}


int
ngx_zookeeper_lua_epoch()
{
    return ngx_http_zmcf()->epoch;
}


void *
ngx_zookeeper_lua_handle()
{
    return ngx_http_zmcf()->handle;
}


ngx_int_t
ngx_zookeeper_lua_init(ngx_conf_t *cf)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    if (ngx_http_lua_add_package_preload(cf, "ngx.zookeeper",
                                         ngx_zookeeper_lua_create_module)
        != NGX_OK)
        return NGX_ERROR;

    zmcf = ngx_http_conf_get_module_main_conf(cf, ngx_zookeeper_lua_module);

    ngx_conf_init_value(zmcf->recv_timeout, 10000);

    return NGX_OK;
}


static void
ngx_log_message(const char *s)
{
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, s);
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
        return "Error while marshalling or unmarshalling data";
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

    return "Unknown";
}

static void
ngx_zookeeper_register_set_ready(int rc, const struct Stat *stat, const void *data)
{
    ngx_zoo_node_t  *node = (ngx_zoo_node_t *) data;

    if (rc == ZOK) {

        if (!node->ephemeral)
            node->epoch = ngx_http_zmcf()->epoch;

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            node->update_fmt, node->node, node->data);

        return;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                  "Zookeeper can't create %s node %s: %s",
                  node->ephemeral ? "ephemeral" : "regular",
                  node->node, ngx_zerr(rc));
}


static void
ngx_zookeeper_register_create_ready(int rc, const char *value, const void *data)
{
    ngx_zoo_node_t                      *node;
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    node = (ngx_zoo_node_t *) data;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (rc == ZOK || rc == ZNODEEXISTS) {

        if (node == NULL)
            return;

        if (rc == ZOK) {

            node->epoch = ngx_http_zmcf()->epoch;

            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                node->fmt, node->node, node->data);

            return;

        } else if (node->may_be_updated) {

            rc = zoo_aset(zmcf->zoo.handle, node->node, node->data,
                strlen(node->data), -1, ngx_zookeeper_register_set_ready, node);

            if (rc != ZOK)
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "Zookeeper: error register instance: %s",
                              ngx_zerr(rc));

            return;
        }
    }

    if (node != NULL) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "Zookeeper can't create %s node %s: %s",
                      node->ephemeral ? "ephemeral" : "regular",
                      node->node, ngx_zerr(rc));
    } else {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "Zookeeper can't create node %s: %s",
                      value != NULL ? value : "???", ngx_zerr(rc));
    }
}


static ngx_int_t
initialize(volatile ngx_cycle_t *cycle);


static void
ngx_zookeeper_delete_ready(int rc, const void *data);

static void
ngx_zookeeper_register_node(ngx_log_t *log, ngx_zoo_node_t *node)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    const char                         **path;
    int                                  rc;
    ngx_uint_t                           j;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    path = node->path->elts;

    for (j = 0; j < node->path->nelts; ++j) {

        rc = zoo_acreate(zmcf->zoo.handle, path[j], "", 0,
           &ZOO_OPEN_ACL_UNSAFE, 0, ngx_zookeeper_register_create_ready,
            NULL);

        if (rc != ZOK) {

            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "Zookeeper: error create node %s : %s",
                          path[j], ngx_zerr(rc));
        }
    }

    rc = zoo_acreate(zmcf->zoo.handle, node->node, node->data,
        strlen(node->data), &ZOO_OPEN_ACL_UNSAFE,
        node->ephemeral ? ZOO_EPHEMERAL : 0,
        ngx_zookeeper_register_create_ready, node);

    if (rc != ZOK)
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "Zookeeper: error register instance: %s",
                      ngx_zerr(rc));
}

static void
ngx_zookeeper_monitor(ngx_event_t *ev)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    ngx_zoo_node_t                      *nodes;
    ngx_uint_t                           i;
    ngx_int_t                            delay;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);
    nodes = (ngx_zoo_node_t *) zmcf->nodes->elts;
    delay = zmcf->recv_timeout * 2;

    if (zmcf->inactive_time != NGX_CONF_UNSET /* suspend after inactive time */
        && zmcf->nodes->nelts == 0 /* nothing to register */
        && zmcf->watched->nelts == 0 /* nothing to watch */
        && zmcf->zoo.handle)
    {
        if (zmcf->zoo.last_op + zmcf->inactive_time < ngx_time()) {

            ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                            "Zookeeper: inactive time, disconnect");

            zookeeper_close(zmcf->zoo.handle);

            zmcf->zoo.handle = NULL;
            zmcf->zoo.client_id = NULL;
            zmcf->zoo.expired = 1;
            zmcf->zoo.connected = NGX_DECLINED;

            return;
        }
    }

    if (zmcf->zoo.expired) {

        if (zmcf->zoo.handle != NULL) {

            zookeeper_close(zmcf->zoo.handle);
            zmcf->zoo.handle = NULL;
            zmcf->zoo.client_id = 0;
        }

        if (initialize(ngx_cycle) != NGX_OK)
            goto settimer;
    }

    if (ngx_worker != 0)
        goto settimer;

    if (zmcf->nodes->nelts == 0)
        goto settimer;

    if (zmcf->zoo.connected == NGX_ERROR)
        goto settimer;

    for (i = 0; i < zmcf->nodes->nelts; i++) {
        if (nodes[i].timestamp > ngx_time())
            delay = ngx_min(delay, nodes[i].timestamp - ngx_time());
        if (zmcf->zoo.epoch > nodes[i].epoch && nodes[i].timestamp <= ngx_time())
            ngx_zookeeper_register_node(ev->log, nodes + i);
    }

settimer:

    if (ngx_exiting || ngx_terminate || ngx_quit)
        // cleanup
        ngx_memset(ev, 0, sizeof(ngx_event_t));
    else
        ngx_add_timer(ev, delay);
}


static void
ngx_zookeeper_create_ready(int rc, const char *value, const void *p);


static void
session_watcher(zhandle_t *zh,
                int type,
                int state,
                const char *path,
                void* context);


static ngx_int_t
initialize(volatile ngx_cycle_t *cycle)
{
    ngx_http_zookeeper_lua_main_conf_t *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    if (zmcf->zoo.connected == NGX_DECLINED)
        zmcf->zoo.connected = NGX_BUSY;

    zmcf->zoo.handle = zookeeper_init2((const char *) zmcf->hosts.data,
                                       session_watcher,
                                       zmcf->recv_timeout,
                                       zmcf->zoo.client_id,
                                       0,
                                       zmcf->init_flags,
                                       ngx_log_message);

    if (zmcf->zoo.handle == NULL) {

        u_char err[1024];

        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "Zookeeper: error create zookeeper handle: %s",
                      ngx_strerror(errno, err, sizeof(err)));

        zmcf->zoo.connected = NGX_ERROR;

        return NGX_ERROR;
    }

    zmcf->zoo.expired = 0;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper: connecting");

    return NGX_OK;
}


static void
session_watcher(zhandle_t *zh,
                int type,
                int state,
                const char *path,
                void *p)
{
    zookeeper_t  *zoo = ngx_http_zmcf();

    if (type == ZOO_SESSION_EVENT) {

        if (state == ZOO_CONNECTED_STATE) {

            zoo->connected = NGX_OK;
            zoo->epoch = zoo->epoch + 1;
            zoo->client_id = zoo_client_id(zh);

            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "Zookeeper: connected");

        } else if (state == ZOO_CONNECTING_STATE) {

            if (zoo->connected != NGX_ERROR) {
                ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                              "Zookeeper: disconnected");
            }

            zoo->connected = NGX_ERROR;

        } else if (state == ZOO_EXPIRED_SESSION_STATE) {

            if (zh != NULL) {

                ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                              "Zookeeper: session has been expired");

                zoo->connected = NGX_ERROR;
                zoo->expired = 1;
                zoo->client_id = NULL;
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
    ngx_http_zookeeper_lua_main_conf_t *zmcf;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    zmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    if (zmcf == NULL || zmcf->hosts.len == 0)
        return NGX_OK;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been initialized in %s mode",
                  zmcf->init_flags == ZOO_READONLY ? "ro" : "rw");

    zmcf->ev.log = cycle->log;

    if (ngx_worker != 0) {
        zmcf->nodes->nelts = 0;
        zmcf->nodes->elts = NULL;
    }

    if (zmcf->inactive_time == NGX_CONF_UNSET || zmcf->nodes->nelts != 0) {
        initialize(cycle);
        ngx_add_timer(&zmcf->ev, 1000);
    } else {
        ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Zookeeper connector suspended");
    }

    return NGX_OK;
}


void
ngx_zookeeper_lua_exit_worker(ngx_cycle_t *cycle)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_zookeeper_lua_module);

    if (zmcf->ev.timer_set)
        ngx_del_timer(&zmcf->ev);

    if (zmcf->zoo.handle == NULL)
        return;

    zookeeper_close(zmcf->zoo.handle);
    zmcf->zoo.handle = NULL;

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "Zookeeper connector has been destroyed");
}


static int ngx_zookeeper_connected(lua_State *L);

static int ngx_zookeeper_suspended(lua_State *L);

static int ngx_zookeeper_resume(lua_State *L);

static int ngx_zookeeper_aget(lua_State *L);

static int ngx_zookeeper_aset(lua_State *L);

static int ngx_zookeeper_aget_childrens(lua_State *L);

static int ngx_zookeeper_acreate(lua_State *L);

static int ngx_zookeeper_adelete(lua_State *L);

static int ngx_zookeeper_atree(lua_State *L);

static int ngx_zookeeper_check_completition(lua_State *L);

static int ngx_zookeeper_timeout(lua_State *L);

static int ngx_zookeeper_addrs(lua_State *L);

static int ngx_zookeeper_hostname(lua_State *L);

static int ngx_zookeeper_awatch(lua_State *L);

static int ngx_zookeeper_aunwatch(lua_State *L);

static int ngx_zookeeper_changed(lua_State *L);

#ifndef OPENRESTY_LUAJIT
#if !defined LUA_VERSION_NUM || LUA_VERSION_NUM < 502

static void
luaL_setfuncs(lua_State *l, const luaL_Reg *reg, int nup)
{
    int  i;

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

    lua_newtable(L);

    lua_pushcfunction(L, ngx_zookeeper_connected);
    lua_setfield(L, -2, "connected");

    lua_pushcfunction(L, ngx_zookeeper_suspended);
    lua_setfield(L, -2, "suspended");

    lua_pushcfunction(L, ngx_zookeeper_resume);
    lua_setfield(L, -2, "resume");

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

    lua_pushcfunction(L, ngx_zookeeper_atree);
    lua_setfield(L, -2, "atree");

    lua_pushcfunction(L, ngx_zookeeper_check_completition);
    lua_setfield(L, -2, "check_completition");

    lua_pushcfunction(L, ngx_zookeeper_timeout);
    lua_setfield(L, -2, "timeout");

    lua_pushcfunction(L, ngx_zookeeper_addrs);
    lua_setfield(L, -2, "addrs");

    lua_pushcfunction(L, ngx_zookeeper_hostname);
    lua_setfield(L, -2, "hostname");

    lua_pushcfunction(L, ngx_zookeeper_awatch);
    lua_setfield(L, -2, "awatch");

    lua_pushcfunction(L, ngx_zookeeper_aunwatch);
    lua_setfield(L, -2, "aunwatch");

    lua_pushcfunction(L, ngx_zookeeper_changed);
    lua_setfield(L, -2, "changed");

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


struct datatype_s
{
    ngx_flag_t       completed;
    ngx_atomic_t     ops;
    completition_t   completition_fn;

    struct Stat      stat;
    void            *data;
    const char      *error;

    ngx_atomic_t               lock;
    volatile ngx_atomic_int_t  refs;
    ngx_pool_t                *pool;
};
typedef struct datatype_s datatype_t;

struct datatype_lua_s
{
    datatype_t  *inner;
};
typedef struct datatype_lua_s datatype_lua_t;


static void
dereference(datatype_t *data)
{
//  ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "deref: 0x%p, refs=%l",
//                data, data->refs);
    if (1 == ngx_atomic_fetch_add(&data->refs, -1)) {
//      ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "dealloc: 0x%p", data);
        ngx_destroy_pool(data->pool);
    }
}


static int
delete(lua_State *L)
{
    datatype_lua_t  *ud = luaL_checkudata(L, 1, "ngx_zoo");
//  ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "lua delete: 0x%p",
//                ud->inner);
    dereference(ud->inner);
    return 0;
}


static datatype_t *
new(lua_State *L)
{
    datatype_lua_t  *ud;
    ngx_pool_t      *pool;

    ud = (datatype_lua_t *) lua_newuserdata(L, sizeof(datatype_lua_t));
    if (ud == NULL)
        return NULL;

    pool = ngx_create_pool(2048, ngx_cycle->log);
    if (pool == NULL)
        return NULL;

    ud->inner = ngx_pcalloc(pool, sizeof(datatype_t));
    if (ud->inner == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ud->inner->refs = 2;
    ud->inner->pool = pool;

    luaL_getmetatable(L, "ngx_zoo");
    lua_setmetatable(L, -2);

//  ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "alloc: 0x%p", ud->inner);

    return ud->inner;
}


static int
ngx_zookeeper_connected(lua_State *L)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (lua_gettop(L))
        return ngx_zookeeper_lua_error(L, "connected", "no arguments expected");

    lua_pushboolean(L, zmcf->hosts.len != 0 /* not configured */ &&
        (!zmcf->ev.timer_set /* suspended */ || (zmcf->zoo.handle && zmcf->zoo.connected != NGX_ERROR)));

    return 1;
}


static int
ngx_zookeeper_suspended(lua_State *L)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (lua_gettop(L))
        return ngx_zookeeper_lua_error(L, "suspended", "no arguments expected");

    lua_pushboolean(L, !zmcf->ev.timer_set);

    return 1;
}


static int
ngx_zookeeper_resume(lua_State *L)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (lua_gettop(L))
        return ngx_zookeeper_lua_error(L, "resume", "no arguments expected");

    if (!zmcf->ev.timer_set) {
        zmcf->zoo.last_op = ngx_time();
        ngx_zookeeper_monitor(&zmcf->ev);
    }

    return 0;
}


static void
ngx_zookeeper_push_stat(lua_State *L, const struct Stat *stat)
{
    lua_createtable(L, 0, 11);

    lua_pushliteral(L, "czxid");
    lua_pushinteger(L, stat->czxid);
    lua_rawset(L, -3);

    lua_pushliteral(L, "mzxid");
    lua_pushinteger(L, stat->mzxid);
    lua_rawset(L, -3);

    lua_pushliteral(L, "ctime");
    lua_pushinteger(L, stat->ctime);
    lua_rawset(L, -3);

    lua_pushliteral(L, "mtime");
    lua_pushinteger(L, stat->mtime);
    lua_rawset(L, -3);

    lua_pushliteral(L, "version");
    lua_pushinteger(L, stat->version);
    lua_rawset(L, -3);

    lua_pushliteral(L, "cversion");
    lua_pushinteger(L, stat->cversion);
    lua_rawset(L, -3);

    lua_pushliteral(L, "aversion");
    lua_pushinteger(L, stat->aversion);
    lua_rawset(L, -3);

    lua_pushliteral(L, "ephemeralOwner");
    lua_pushinteger(L, stat->ephemeralOwner);
    lua_rawset(L, -3);

    lua_pushliteral(L, "dataLength");
    lua_pushinteger(L, stat->dataLength);
    lua_rawset(L, -3);

    lua_pushliteral(L, "numChildren");
    lua_pushinteger(L, stat->numChildren);
    lua_rawset(L, -3);

    lua_pushliteral(L, "pzxid");
    lua_pushinteger(L, stat->pzxid);
    lua_rawset(L, -3);
}


static int
ngx_zookeeper_check_completition(lua_State *L)
{
    datatype_lua_t   *ud;
    datatype_t       *data;
    zookeeper_t      *zoo = ngx_http_zmcf();
    int               n = 3;

    zoo->last_op = ngx_time();

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "exactly one arguments expected");

    if (!lua_isuserdata(L, 1))
        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "argument must be a userdata");

    ud = (datatype_lua_t *) luaL_checkudata(L, 1, "ngx_zoo");
    if (ud == NULL)
        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "argument is not a zookeeper type");

    data = ud->inner;

    ngx_rwlock_wlock(&data->lock);

    if (zoo->handle == NULL) {

        ngx_rwlock_unlock(&data->lock);

        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "zookeeper handle is nil");
    }

    if (zoo->connected == NGX_ERROR) {

        ngx_rwlock_unlock(&data->lock);

        return ngx_zookeeper_lua_error(L, "check_completition",
                                       "not connected");
    }

    lua_pushboolean(L, data->completed);

    if (!data->completed) {

        ngx_rwlock_unlock(&data->lock);
        return 1;
    }

    if (data->error == NULL) {

        if (data->data != NULL) {

            data->completition_fn(L, data->data);
            lua_pushnil(L);

        } else {

            lua_pushnil(L);
            lua_pushnil(L);
        }

        if (data->stat.pzxid) {

            ngx_zookeeper_push_stat(L, &data->stat);
            n++;
        }

        goto done;
    }

    lua_pushnil(L);
    lua_pushlstring(L, data->error, strlen(data->error));

done:

    return n;
}


static int
ngx_zookeeper_timeout(lua_State *L)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
        ngx_zookeeper_lua_module);

    lua_pushinteger(L, zmcf->recv_timeout);

    return 1;
}


static int
ngx_zookeeper_addrs(lua_State *L)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    ngx_uint_t                           j;

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

    if (data->refs == 1)
        goto end;

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

    data->error = "no memory";

end:

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

    dereference(data);
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

    if (data->refs == 1)
        goto end;

    ngx_rwlock_wlock(&data->lock);

    if (rc != ZOK)
        data->error = ngx_zerr(rc);

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

end:

    dereference(data);
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
    int           rc;
    datatype_t   *data;
    str_t         path;
    zookeeper_t  *zoo;

    ngx_http_zookeeper_check_mon();

    zoo = ngx_http_zmcf();

    if (zoo->handle == NULL)
        return ngx_zookeeper_lua_error(L, "aget", "zookeeper handle is nil");

    if (zoo->connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "aget", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "aget",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "aget", "no memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    data->completition_fn = ngx_zookeeper_get_completition;

    rc = zoo_aget(zoo->handle, path.data, 0,
        ngx_zookeeper_get_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data);

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

    if (data->refs == 1)
        goto end;

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

    data->error = "no memory";

end:

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

    dereference(data);
}


static int
ngx_zookeeper_aget_childrens(lua_State *L)
{
    int           rc;
    datatype_t   *data;
    str_t         path;
    zookeeper_t  *zoo;

    ngx_http_zookeeper_check_mon();

    zoo = ngx_http_zmcf();

    if (zoo->handle == NULL)
        return ngx_zookeeper_lua_error(L, "aget_childrens",
                                       "zookeeper handle is nil");

    if (zoo->connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "aget_childrens", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "aget_childrens",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "aget_childrens", "no memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    data->completition_fn = ngx_zookeeper_get_childrens_completition;

    rc = zoo_aget_children(zoo->handle, path.data, 0,
        ngx_zookeeper_get_childrens_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data);

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

    if (data->refs == 1)
        goto end;

    ngx_rwlock_wlock(&data->lock);

    if (rc == ZOK) {

        if (stat)
            ngx_memcpy(&data->stat, stat, sizeof(struct Stat));

    } else
        data->error = ngx_zerr(rc);

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

end:
    
    dereference(data);
}


static int
ngx_zookeeper_aset(lua_State *L)
{
    int           rc;
    lua_Integer   version = -1;
    str_t         value;
    datatype_t   *data;
    str_t         path;
    zookeeper_t  *zoo;

    ngx_http_zookeeper_check_mon();

    zoo = ngx_http_zmcf();

    if (zoo->handle == NULL)
        return ngx_zookeeper_lua_error(L, "aset", "zookeeper handle is nil");

    if (zoo->connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "aset", "not connected");

    rc = lua_gettop(L); 

    if (rc != 2 && rc != 3)
        return ngx_zookeeper_lua_error(L, "aset",
            "exactly 2 or 3 arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "aset", "no memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    value.data = (char *) luaL_checklstring(L, 2, &value.len);

    if (rc == 3)
        version = luaL_checkinteger(L, 3);

    data->completition_fn = ngx_zookeeper_set_completition;

    rc = zoo_aset(zoo->handle, path.data, value.data, value.len, version,
                  ngx_zookeeper_set_ready, data);
    if (rc == ZOK) {
        return 1;
    }

    dereference(data);

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
    int           rc, flags = 0;
    str_t         value;
    datatype_t   *data;
    str_t         path;
    zookeeper_t  *zoo;

    ngx_http_zookeeper_check_mon();

    zoo = ngx_http_zmcf();

    if (zoo->handle == NULL)
        return ngx_zookeeper_lua_error(L, "acreate", "zookeeper handle is nil");

    if (zoo->connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "acreate", "not connected");

    if (lua_gettop(L) != 2 && lua_gettop(L) != 3)
        return ngx_zookeeper_lua_error(L, "acreate",
                                       "exactly 2 or 3 arguments expected");

    if (lua_gettop(L) == 3)
        flags = luaL_checkinteger(L, 3);

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "acreate", "no memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);
    value.data = (char *) luaL_checklstring(L, 2, &value.len);

    data->completition_fn = ngx_zookeeper_create_completition;

    rc = zoo_acreate(zoo->handle, path.data, value.data, value.len,
        &ZOO_OPEN_ACL_UNSAFE, flags, ngx_zookeeper_create_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data);

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
    int           rc;
    datatype_t   *data;
    str_t         path;
    zookeeper_t  *zoo;

    ngx_http_zookeeper_check_mon();

    zoo = ngx_http_zmcf();

    if (zoo->handle == NULL)
        return ngx_zookeeper_lua_error(L, "adelete", "zookeeper handle is nil");

    if (zoo->connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "adelete", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "adelete",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "adelete", "no memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);

    data->completition_fn = ngx_zookeeper_delete_completition;

    rc = zoo_adelete(zoo->handle, path.data, -1,
                     ngx_zookeeper_delete_ready, data);
    if (rc == ZOK)
        return 1;

    dereference(data);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "adelete", ngx_zerr(rc));
}


//------------------------------------------------------------------------------


struct ngx_zoo_tree_node_s {
    datatype_t                  *data;
    ngx_array_t                 *childrens;
    str_t                        value;
    str_t                        name;
    str_t                        path;
    struct Stat                  stat;
};
typedef struct ngx_zoo_tree_node_s ngx_zoo_tree_node_t;


static void
ngx_zookeeper_tree_push(lua_State *L, ngx_zoo_tree_node_t *node)
{
    ngx_zoo_tree_node_t  *childrens;
    ngx_uint_t            j;

    lua_newtable(L);

    lua_pushlstring(L, node->value.data, node->value.len);
    lua_setfield(L, -2, "__value");

    ngx_zookeeper_push_stat(L, &node->stat);
    lua_setfield(L, -2, "__stat");

    if (node->childrens == NULL)
        return;

    childrens = node->childrens->elts;

    for (j = 0; j < node->childrens->nelts; j++) {

        lua_pushlstring(L, childrens[j].name.data, childrens[j].name.len);
        ngx_zookeeper_tree_push(L, childrens + j);
        lua_rawset(L, -3);
    }
}


static void
ngx_zookeeper_tree_completition(lua_State *L, void *p)
{
    ngx_zoo_tree_node_t  *node = (ngx_zoo_tree_node_t *) p;
    ngx_zookeeper_tree_push(L, node);
}


static void
ngx_zookeeper_tree_get_ready(int rc, const char *value, int value_len,
    const struct Stat *stat, const void *p);


static void
ngx_zookeeper_tree_childrens_ready(int rc, const struct String_vector *strings,
    const void *p)
{
    ngx_zoo_tree_node_t  *parent = (ngx_zoo_tree_node_t *) p;
    ngx_zoo_tree_node_t  *node;
    ngx_int_t             j;
    datatype_t           *data;
    zookeeper_t          *zoo;

    zoo = ngx_http_zmcf();

    data = parent->data;

    ngx_rwlock_wlock(&data->lock);

    if (data->refs == 1)
        goto end;

    if (rc != ZOK)
        goto err;

    parent->childrens = ngx_array_create(data->pool,
        strings->count, sizeof(ngx_zoo_tree_node_t));
    if (parent->childrens == NULL)
        goto nomem;

    for (j = 0; j < strings->count; j++) {

        node = ngx_array_push(parent->childrens);
        if (node == NULL)
            goto nomem;

        ngx_memzero(node, sizeof(ngx_zoo_tree_node_t));
        node->data = parent->data;

        // node name
        node->name.len = strlen(strings->data[j]);
        node->name.data = ngx_pcalloc(data->pool, node->name.len + 1);
        if (node->name.data == NULL)
            goto nomem;
        ngx_memcpy(node->name.data, strings->data[j], node->name.len);

        // node zpath
        node->path.len = parent->path.len + 1 + node->name.len;
        node->path.data = ngx_pcalloc(data->pool, node->path.len + 1);
        if (node->path.data == NULL)
            goto nomem;
        ngx_memcpy(node->path.data, parent->path.data, parent->path.len);
        node->path.data[parent->path.len] = '/';
        ngx_memcpy(node->path.data + parent->path.len + 1, node->name.data,
            node->name.len);

        ngx_atomic_fetch_add(&data->ops, 1);

        rc = zoo_aget(zoo->handle, node->path.data, 0,
            ngx_zookeeper_tree_get_ready, node);
        if (rc != ZOK) {
            ngx_atomic_fetch_add(&data->ops, -1);
            goto err;
        }
    }

    goto end;

err:

    data->error = ngx_zerr(rc);

    goto end;

nomem:

    data->error = "no memory";

end:

    data->completed = ngx_atomic_fetch_add(&data->ops, -1) == 1;

    ngx_rwlock_unlock(&data->lock);

    if (data->completed)
        dereference(data);
}


static void
ngx_zookeeper_tree_get_ready(int rc, const char *value, int value_len,
    const struct Stat *stat, const void *p)
{
    ngx_zoo_tree_node_t  *node = (ngx_zoo_tree_node_t *) p;
    datatype_t           *data;
    zookeeper_t          *zoo;

    zoo = ngx_http_zmcf();

    data = node->data;

    ngx_rwlock_wlock(&data->lock);

    if (data->refs == 1)
        goto end;

    if (rc != ZOK)
        goto err;

    if (value != NULL && value_len != 0) {

        node->value.data = ngx_pcalloc(data->pool, value_len);
        if (node->value.data == NULL)
            goto nomem;

        ngx_memcpy(node->value.data, value, value_len);
        node->value.len = value_len;
    } else {

        node->value.data = "";
    }

    ngx_memcpy(&node->stat, stat, sizeof(struct Stat));

    if (stat->numChildren == 0)
        goto end;

    ngx_atomic_fetch_add(&data->ops, 1);

    if (node->path.data[node->path.len - 1] == '/')
        node->path.len--;

    rc = zoo_aget_children(zoo->handle, node->path.data, 0,
        ngx_zookeeper_tree_childrens_ready, node);
    if (rc != ZOK) {
        ngx_atomic_fetch_add(&data->ops, -1);
        goto err;
    }

    goto end;

err:

    data->error = ngx_zerr(rc);

    goto end;

nomem:

    data->error = "no memory";

end:

    data->completed = ngx_atomic_fetch_add(&data->ops, -1) == 1;

    ngx_rwlock_unlock(&data->lock);

    if (data->completed)
        dereference(data);
}


static int
ngx_zookeeper_atree(lua_State *L)
{
    int                   rc;
    datatype_t           *data;
    str_t                 path;
    ngx_zoo_tree_node_t  *node;
    zookeeper_t          *zoo;

    ngx_http_zookeeper_check_mon();

    zoo = ngx_http_zmcf();

    if (zoo->handle == NULL)
        return ngx_zookeeper_lua_error(L, "atree",
                                       "zookeeper handle is nil");

    if (zoo->connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "atree", "not connected");

    if (lua_gettop(L) != 1)
        return ngx_zookeeper_lua_error(L, "atree",
                                       "exactly one arguments expected");

    data = new(L);
    if (data == NULL)
        return ngx_zookeeper_lua_error(L, "atree", "no memory");

    node = ngx_pcalloc(data->pool, sizeof(ngx_zoo_tree_node_t));
    if (node == NULL)
        return ngx_zookeeper_lua_error(L, "atree", "no memory");

    path.data = (char *) luaL_checklstring(L, 1, &path.len);

    node->path.data = ngx_pcalloc(data->pool, path.len + 1);
    if (node->path.data == NULL)
        return ngx_zookeeper_lua_error(L, "atree", "no memory");

    ngx_memcpy(node->path.data, path.data, path.len);
    node->path.len = path.len;

    node->data = data;
    data->completition_fn = ngx_zookeeper_tree_completition;
    data->ops = 1;
    data->data = node;

    rc = zoo_aget(zoo->handle, node->path.data, 0,
        ngx_zookeeper_tree_get_ready, node);
    if (rc == ZOK)
        return 1;

    dereference(data);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "atree", ngx_zerr(rc));
}


typedef struct {
    datatype_t  *data;
    ngx_int_t    index;
} watch_ready_context_t;


static void
ngx_zookeeper_watch(zhandle_t *zh, int type,
    int state, const char *path, void *ctxp)
{
    ngx_int_t                            index = (ngx_int_t) ctxp;
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    watched_t                           *w;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (type == ZOO_CHILD_EVENT
        || type == ZOO_CHANGED_EVENT
        || type == ZOO_DELETED_EVENT) {

        ngx_rwlock_wlock(&zmcf->lock);

        w = ((watched_t *) zmcf->watched->elts) + index;
        if (w->path.data && w->watch_type == type && ngx_strncmp(path, w->path.data, w->path.len) == 0)
            w->changed = 1;

        ngx_rwlock_unlock(&zmcf->lock);
    }
}


static void
ngx_zookeeper_awatch_free_slot(watched_t *w)
{
    ngx_free(w->path.data);
    ngx_str_null(&w->path);
    w->changed = 0;
    w->watch_type = 0;
}


static void 
ngx_zookeeper_watch_ready(int rc, watch_ready_context_t *ctx)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    watched_t                           *w;

    if (rc == ZOK)
        return;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    ngx_rwlock_wlock(&zmcf->lock);

    w = zmcf->watched->elts;

    ngx_zookeeper_awatch_free_slot(w + ctx->index);

    ngx_rwlock_unlock(&zmcf->lock);
}


static void
ngx_zookeeper_watch_data_ready(int rc, const char *value, int value_len,
    const struct Stat *stat, const void *ctxp)
{
    watch_ready_context_t  *ctx = (watch_ready_context_t *) ctxp;

    ngx_zookeeper_watch_ready(rc, ctx);

    return ngx_zookeeper_get_ready(rc, value, value_len, stat, ctx->data);
}


static void
ngx_zookeeper_watch_children_ready(int rc, const struct String_vector *strings,
    const void *ctxp)
{
    watch_ready_context_t  *ctx = (watch_ready_context_t *) ctxp;

    ngx_zookeeper_watch_ready(rc, ctx);

    return ngx_zookeeper_get_childrens_ready(rc, strings, ctx->data);
}


static ngx_int_t
ngx_zookeeper_awatch_exists(str_t path, int watch_type)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    watched_t                           *w;
    ngx_uint_t                           j;
    ngx_str_t                            s = { path.len, (u_char *) path.data };

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    w = zmcf->watched->elts;

    for (j = 0; j < zmcf->watched->nelts; j++)
        if (str_eq(s, w[j].path) && w[j].watch_type == watch_type)
            return j;
 
    return NGX_DECLINED;
}


static ngx_int_t
ngx_zookeeper_awatch_slot()
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    watched_t                           *w;
    ngx_uint_t                           j;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    w = zmcf->watched->elts;

    for (j = 0; j < zmcf->watched->nelts; j++)
        if (w[j].path.data == NULL)
            return j;
 
    w = ngx_array_push(zmcf->watched);
    if (w != NULL)
        return zmcf->watched->nelts - 1;

    return NGX_ERROR;
}


static int
ngx_zookeeper_awatch(lua_State *L)
{
    int                                  rc;
    datatype_t                          *data = NULL;
    str_t                                path;
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    watched_t                           *w;
    watch_ready_context_t               *ctx;
    int                                  watch_type;

    ngx_http_zookeeper_check_mon();

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (zmcf->zoo.handle == NULL)
        return ngx_zookeeper_lua_error(L, "awatch", "zookeeper handle is nil");

    if (zmcf->zoo.connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "awatch", "not connected");

    if (lua_gettop(L) != 2)
        return ngx_zookeeper_lua_error(L, "awatch", "2 arguments expected");

    watch_type = luaL_checkinteger(L, 2);

    if (watch_type != ZOO_CHILD_EVENT && watch_type != ZOO_CHANGED_EVENT)
        return ngx_zookeeper_lua_error(L, "awatch", "invalid watch type");

    ngx_rwlock_wlock(&zmcf->lock);

    path.data = (char *) luaL_checklstring(L, 1, &path.len);

    if (ngx_zookeeper_awatch_exists(path, watch_type) != NGX_DECLINED) {

        ngx_rwlock_unlock(&zmcf->lock);
        return ngx_zookeeper_lua_error(L, "awatch", "exists");
    }

    data = new(L);
    if (data == NULL)
        goto nomem;

    ctx = ngx_pcalloc(data->pool, sizeof(watch_ready_context_t));
    if (ctx == NULL)
        goto nomem;

    ctx->index = ngx_zookeeper_awatch_slot();
    if (ctx->index == NGX_ERROR)
        goto nomem;

    w = ((watched_t *) zmcf->watched->elts) + ctx->index;

    ctx->data = data;

    w->path.len = path.len;
    w->path.data = ngx_calloc(path.len + 1, ngx_cycle->log);
    if (w->path.data == NULL)
        goto nomem;
    ngx_memcpy(w->path.data, path.data, path.len);
    w->watch_type = watch_type;
    w->changed = 0;

    if (watch_type == ZOO_CHANGED_EVENT) {

        data->completition_fn = ngx_zookeeper_get_completition;
        rc = zoo_awget(zmcf->zoo.handle, path.data,
            ngx_zookeeper_watch, (void *) ctx->index,
            ngx_zookeeper_watch_data_ready, ctx);

    } else {

        data->completition_fn = ngx_zookeeper_get_childrens_completition;
        rc = zoo_awget_children(zmcf->zoo.handle, path.data,
            ngx_zookeeper_watch, (void *) ctx->index,
            ngx_zookeeper_watch_children_ready, ctx);

    }

    if (rc == ZOK) {

        ngx_rwlock_unlock(&zmcf->lock);
        return 1;
    }

    ngx_zookeeper_awatch_free_slot(w);

    ngx_rwlock_unlock(&zmcf->lock);

    dereference(data);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "awatch", ngx_zerr(rc));

nomem:

    ngx_rwlock_unlock(&zmcf->lock);

    if (data != NULL) {

        dereference(data);

        /* pop userdata */
        lua_pop(L, 1);
    }

    return ngx_zookeeper_lua_error(L, "awatch", "no memory");
}


static void
ngx_zookeeper_unwatch_ready(int rc, const void *p)
{
    datatype_t  *data = (datatype_t *) p;

    if (data == NULL)
        return;

    if (data->refs == 1)
        goto end;

    ngx_rwlock_wlock(&data->lock);

    if (rc != ZOK && rc != ZUNIMPLEMENTED)
        data->error = ngx_zerr(rc);

    data->completed = 1;

    ngx_rwlock_unlock(&data->lock);

end:

    dereference(data);
}


static int
ngx_zookeeper_aunwatch(lua_State *L)
{
    int                                  rc;
    datatype_t                          *data;
    str_t                                path;
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    int                                  watch_type;
    ngx_int_t                            index;
    watched_t                           *w;

    ngx_http_zookeeper_check_mon();

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (zmcf->zoo.handle == NULL)
        return ngx_zookeeper_lua_error(L, "aunwatch",
                                       "zookeeper handle is nil");

    if (zmcf->zoo.connected == NGX_ERROR)
        return ngx_zookeeper_lua_error(L, "aunwatch", "not connected");

    if (lua_gettop(L) != 2)
        return ngx_zookeeper_lua_error(L, "aunwatch",
                                       "2 arguments expected");

    watch_type = luaL_checkinteger(L, 2);

    if (watch_type != ZOO_CHILD_EVENT && watch_type != ZOO_CHANGED_EVENT)
        return ngx_zookeeper_lua_error(L, "aunwatch", "invalid watch type");

    ngx_rwlock_wlock(&zmcf->lock);

    path.data = (char *) luaL_checklstring(L, 1, &path.len);

    index = ngx_zookeeper_awatch_exists(path, watch_type);
    if (index == NGX_DECLINED) {

        ngx_rwlock_unlock(&zmcf->lock);
        return ngx_zookeeper_lua_error(L, "aunwatch", "not exists");
    }

    data = new(L);
    if (data == NULL) {

        ngx_rwlock_unlock(&zmcf->lock);
        return ngx_zookeeper_lua_error(L, "aunwatch", "no memory");
    }

    data->completition_fn = ngx_zookeeper_void_completition;

    rc = zoo_aremove_watches(zmcf->zoo.handle, path.data, watch_type,
        ngx_zookeeper_watch, (void *) index, 0,
        (void_completion_t *) ngx_zookeeper_unwatch_ready, data);

    if (rc == ZOK || rc == ZNOWATCHER) {

        w = zmcf->watched->elts;

        ngx_zookeeper_awatch_free_slot(w + index);

        if (rc == ZNOWATCHER) {

            dereference(data);
            data->completed = 1;
        }

        ngx_rwlock_unlock(&zmcf->lock);
        return 1;
    }

    ngx_rwlock_unlock(&zmcf->lock);

    dereference(data);

    /* pop userdata */
    lua_pop(L, 1);

    return ngx_zookeeper_lua_error(L, "aunwatch", ngx_zerr(rc));
}


static int
ngx_zookeeper_changed(lua_State *L)
{
    ngx_http_zookeeper_lua_main_conf_t  *zmcf;
    watched_t                           *w;
    ngx_uint_t                           j;
    int                                  i = 1, used_slots = 0;

    zmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_zookeeper_lua_module);

    if (lua_gettop(L))
        return ngx_zookeeper_lua_error(L, "changed", "no arguments expected");

    w = zmcf->watched->elts;

    lua_newtable(L);

    ngx_rwlock_wlock(&zmcf->lock);

    for (j = 0; j < zmcf->watched->nelts; j++) {

        if (w[j].path.data)
            used_slots++;

        if (!w[j].changed || !w[j].path.data)
            continue;

        lua_newtable(L);

        lua_pushlstring(L, (char *) w[j].path.data, w[j].path.len);
        lua_rawseti(L, -2, 1);

        lua_pushinteger(L, w[j].watch_type);
        lua_rawseti(L, -2, 2);

        lua_rawseti(L, -2, i++);

        ngx_zookeeper_awatch_free_slot(w + j);
    }

    if (used_slots == 0)
        zmcf->watched->nelts = 0;

    ngx_rwlock_unlock(&zmcf->lock);

    return 1;
}
