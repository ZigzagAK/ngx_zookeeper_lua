#include <ngx_core.h>
#include <ngx_http.h>
#include <lauxlib.h>
#include <assert.h>
#include <zookeeper/zookeeper.h>

#include "ngx_http_lua_api.h"

#define CAST(p, T) ((T)p)

#define MAX_DATA_SIZE 1048576

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

static void
ngx_log_message(const char *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, s);
}

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
static int ngx_zookeeper_timeout(lua_State * L);
static int ngx_zookeeper_forgot(lua_State * L);

static int
ngx_zookeeper_lua_create_module(lua_State * L)
{
    lua_createtable(L, 0, 8);

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
    lua_pushboolean(L, 0);
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
            rc = 2;
        }
        else
        {
            lua_pushnil(L);
            lua_pushlstring(L, r->error, strlen(r->error));
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
    if (!zoo.handle)
    {
        lua_pushnil(L);
    }
    else
    {
        lua_pushinteger(L, CAST(zoo_recv_timeout(zoo.handle), lua_Integer));
    }

    return 1;
}

//---------------------------------------------------------------------------------------------------------

static void
ngx_zookeeper_string_completition(lua_State * L, void *data)
{
    string_result_t *g_r = (string_result_t *) data;
    if (g_r && g_r->len)
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
    return ngx_zookeeper_string_ready(rc ,value, value_len, stat, data);
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

    lua_pushboolean(L, 1);
    lua_pushinteger(L, CAST(r, lua_Integer));

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

    lua_newtable(L);
    lua_createtable(L, g_r->count, 0);

    for (j = 0; j < g_r->count; ++j)
    {
        lua_pushlstring(L, (char *) g_r->array[j].data, g_r->array[j].len);
        lua_rawseti (L, -2, j);
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

    lua_pushboolean(L, 1);
    lua_pushinteger(L, CAST(r, lua_Integer));

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
    return ngx_zookeeper_void_ready(rc, data);
}

static int
ngx_zookeeper_aset(lua_State * L)
{
    int rc;
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

    if (lua_gettop(L) != 2)
    {
        return ngx_zookeeper_lua_error(L, "aset", "exactly 2 arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "aset", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);
    value.data = luaL_checklstring(L, 2, &value.len);

    r->completition_fn = ngx_zookeeper_set_completition;

    rc = zoo_aset(zoo.handle, path.data, value.data, value.len, -1, ngx_zookeeper_set_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "aset", rc_str_s(rc));
    }

    lua_pushboolean(L, 1);
    lua_pushinteger(L, CAST(r, lua_Integer));

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
    return ngx_zookeeper_string_ready(rc, value, value ? strlen(value) : 0, NULL, data);
}

static int
ngx_zookeeper_acreate(lua_State * L)
{
    int rc;
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

    if (lua_gettop(L) != 2)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "exactly 2 arguments expected");
    }

    r = alloc_result();
    if (!r)
    {
        return ngx_zookeeper_lua_error(L, "acreate", "Failed to allocate memory");
    }

    path.data = luaL_checklstring(L, 1, &path.len);
    value.data = luaL_checklstring(L, 2, &value.len);

    r->completition_fn = ngx_zookeeper_create_completition;

    rc = zoo_acreate(zoo.handle, path.data, value.data, value.len, &ZOO_OPEN_ACL_UNSAFE, 0, ngx_zookeeper_create_ready, r);
    if (rc != ZOK)
    {
        free_result(r);
        return ngx_zookeeper_lua_error(L, "acreate", rc_str_s(rc));
    }

    lua_pushboolean(L, 1);
    lua_pushinteger(L, CAST(r, lua_Integer));

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

    lua_pushboolean(L, 1);
    lua_pushinteger(L, CAST(r, lua_Integer));

    return 2;
}

