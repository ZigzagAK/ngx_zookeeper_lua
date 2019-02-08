local zoo    = require "ngx.zookeeper"
local cjson  = require "cjson"

local ffi = require 'ffi'

local C = ffi.C

ffi.cdef[[
  int usleep(unsigned int usec);
]]

local function blocking_sleep(sec)
  return C.usleep(sec * 1000000)
end

local timeout = zoo.timeout()

local _M = {
  _VERSION = "2.4.0",

  errors = {
    ZOO_OK = "OK",
    ZOO_SYSTEMERROR = "System error",
    ZOO_RUNTIMEINCONSISTENCY = "Runtime inconsistency",
    ZOO_DATAINCONSISTENCY = "Data inconsistency",
    ZOO_CONNECTIONLOSS = "Connection to the server has been lost",
    ZOO_MARSHALLINGERROR = "Error while marshalling or unmarshalling data",
    ZOO_UNIMPLEMENTED = "Operation not implemented",
    ZOO_TIMEOUT = "Operation timeout",
    ZOO_BADARGUMENTS = "Invalid argument",
    ZOO_INVALIDSTATE = "Invalid zhandle state",
    ZOO_APIERROR = "API error",
    ZOO_NONODE = "Znode does not exist",
    ZOO_NOAUTH = "Not authenticated",
    ZOO_BADVERSION = "Version conflict",
    ZOO_NOCHILDRENFOREPHEMERALS = "Ephemeral nodes may not have children",
    ZOO_NODEEXISTS = "Znode already exists",
    ZOO_NOTEMPTY = "The znode has children",
    ZOO_SESSIONEXPIRED = "The session has been expired by the server",
    ZOO_INVALIDCALLBACK = "Invalid callback specified",
    ZOO_INVALIDACL = "Invalid ACL specified",
    ZOO_AUTHFAILED = "Client authentication failed",
    ZOO_CLOSING = "ZooKeeper session is closing",
    ZOO_NOTHING = "No response from server",
    ZOO_SESSIONMOVED = "Session moved to a different server"
  },

  WatcherType = {
    CHILDREN = 1,
    DATA = 2
  },

  flags = {
    ZOO_EPHEMERAL = bit.lshift(1, 0),
    ZOO_SEQUENCE = bit.lshift(1, 1)
  }
}

local errors
local WatcherType
local create
local delete
local delete_recursive
local childrens
local watch
local unwatch
local clear_in_cache

local CACHE = ngx.shared.zoo_cache
local CONFIG = ngx.shared.config

local pcall, xpcall = pcall, xpcall
local ipairs, pairs = ipairs, pairs
local assert = assert
local unpack = unpack
local type = type
local now, update_time = ngx.now, ngx.update_time
local ngx_log = ngx.log
local sleep = ngx.sleep
local WARN, DEBUG = ngx.WARN, ngx.DEBUG
local sub = string.sub
local rep = string.rep
local tconcat, tinsert = table.concat, table.insert
local md5, format = ngx.md5, string.format

local json_decode = cjson.decode
local json_encode = cjson.encode

local zoo_cache_on       = CONFIG:get("zoo.cache.on")
local zoo_cache_ttl      = CONFIG:get("zoo.cache.ttl") or 60
local zoo_cache_path_ttl = json_decode(CONFIG:get("zoo.cache.path.ttl") or {})
local zoo_decode_json    = CONFIG:get("zoo.decode_json")
local zoo_watch_interval = CONFIG:get("zoo.watch.interval") or 1
local zoo_debug          = CONFIG:get("zoo.debug")

local function debug(fun)
  if zoo_debug then
    ngx_log(DEBUG, fun())
  end
end

table.sort(zoo_cache_path_ttl, function(l, r) return #l.path > #r.path end)

local function json_pretty_encode(dt, lf, id, ac)
  local s, e = json_encode(dt)
  if not s then return s, e end
  lf, id, ac = lf or "\n", id or "    ", ac or " "
  local i, j, k, n, r, p, q  = 1, 0, 0, #s, {}, nil, nil
  local al = sub(ac, -1) == "\n"
  for x = 1, n do
    local c = sub(s, x, x)
    if not q and (c == "{" or c == "[") then
      r[i] = p == ":" and tconcat{ c, lf } or tconcat{ rep(id, j), c, lf }
      j = j + 1
    elseif not q and (c == "}" or c == "]") then
      j = j - 1
      if p == "{" or p == "[" then
        i = i - 1
        r[i] = tconcat{ rep(id, j), p, c }
      else
        r[i] = tconcat{ lf, rep(id, j), c }
      end
    elseif not q and c == "," then
      r[i] = tconcat{ c, lf }
      k = -1
    elseif not q and c == ":" then
      r[i] = tconcat{ c, ac }
      if al then
        i = i + 1
        r[i] = rep(id, j)
      end
    else
      if c == '"' and p ~= "\\" then
        q = not q and true or nil
      end
      if j ~= k then
        r[i] = rep(id, j)
        i, k = i + 1, j
      end
      r[i] = c
    end
    p, i = c, i + 1
  end
  return tconcat(r)
end

local function get_ttl(znode)
  for _, z in ipairs(zoo_cache_path_ttl)
  do
    if znode:match(z.path) then
      return z.ttl
    end
  end
  return zoo_cache_ttl
end

local function get_expires()
  update_time()
  return now() * 1000 + timeout
end

local function suspend(sec)
  if not pcall(sleep, sec) then
    ngx_log(WARN, "blocking sleep function is used")
    blocking_sleep(sec)
  end
end

local function zoo_call(fun)
  local sc, err = fun()
  if not sc then
    return nil, err
  end

  local expires = get_expires()
  local completed, value, stat

  repeat
    suspend(0.001)
    if not xpcall(function()
      completed, value, err, stat = zoo.check_completition(sc)
      return true
    end, function(e)
      err = e
      return e
    end) then
      return nil, err
    end
  until completed or now() * 1000 > expires

  if completed then
    return not err and { value, stat } or nil, err
  end

  return nil, errors.ZOO_TIMEOUT
end

function _M.clear_in_cache(znode)
  CACHE:delete("$c:" .. znode)
  CACHE:delete("$v:" .. znode)
end

function _M.clear_cache(prefix)
  if not prefix then
    CACHE:flush_all()
  else
    prefix = "^%$[cv]:" .. prefix
    for _,key in ipairs(CACHE:get_keys(0) or {}) do
      if key:match(prefix) then
        CACHE:delete(key)
      end
    end
  end
  CACHE:flush_expired()
end

local function save_in_cache(prefix, znode, v, stat)
  if not zoo_cache_on then
    return
  end

  local ttl = get_ttl(znode)
  if ttl == 0 then
    return
  end

  local cached = json_encode { stat = stat, value = v }

  local ok, err = CACHE:set(prefix .. ":" .. znode, cached, zoo_cache_ttl)

  if ok then
    debug(function()
      return "zoo set cached: ttl=", ttl, "s,", znode, "=", cached
    end)
  else
    ngx_log(WARN, "zoo set cached: ", err)
  end
end

local function get_from_cache(prefix, znode)
  if zoo_cache_on then
    local cached = CACHE:get(prefix .. ":" .. znode)
    if cached then
      debug(function()
        return "zoo get cached: ", znode, "=", cached
      end)
      return json_decode(cached)
    end
  end
end

function _M.get(znode, nocache)
  if not nocache then
    local cached = get_from_cache("$v", znode)
    if cached then
      return cached.value, cached.stat
    end
  end

  local data, err = zoo_call(function()
    return zoo.aget(znode)
  end)

  if not data then
    return nil, nil, err
  end

  local value, stat = unpack(data)

  debug(function()
    return "zoo get: ", znode, "=", value
  end)

  if zoo_decode_json and value and value:match("^%s*{") then
    -- may be json
    local ok, object = pcall(json_decode, value)
    if ok then
      -- value is valid object
      value = object
    end
  end

  save_in_cache("$v", znode, value or "", stat)

  return value or "", stat
end

function _M.childrens(znode, nocache)
  if not nocache then
    local cached = get_from_cache("$c", znode)
    if cached then
      return cached.value or {}
    end
  end

  local data, err = zoo_call(function()
    return zoo.achildrens(znode)
  end)

  if not data then
    return nil, err
  end

  local childs, stat = unpack(data)

  save_in_cache("$c", znode, childs, nil)
  debug(function()
    return "zoo childrens: ", znode, "=", json_encode(childs)
  end)

  return childs or {}
end

function _M.set(znode, value, version)
  value = type(value) == "table" and (
    #value == 0 and json_pretty_encode(value) or tconcat(value, "\n")
  ) or value or ""

  local data, err = zoo_call(function()
    return zoo.aset(znode, value, version or -1)
  end)

  clear_in_cache(znode)

  return data and data[2] or nil, err
end

function _M.create(znode, value, flags)
  value = type(value) == "table" and (
    #value == 0 and json_pretty_encode(value) or tconcat(value, "\n")
  ) or value or ""

  local data, err = zoo_call(function()
    return zoo.acreate(znode, value, flags or 0)
  end)

  return data and (data[1] or "") or nil, err
end

function _M.create_path(znode)
  local path = "/"

  local data, err = zoo_call(function()
    return zoo.aget(znode)
  end)

  if data then
    return true
  end

  if err ~= errors.ZOO_NONODE then
    return nil, err
  end

  for p in znode:gmatch("/([^/]+)")
  do
    local ok, err = create(path .. p)
    if not ok and err ~= errors.ZOO_NODEEXISTS then
      return nil, err
    end
    path = path .. p .. "/"
  end

  return true
end

function _M.delete(znode)
  local data, err = zoo_call(function()
    return zoo.adelete(znode)
  end)

  clear_in_cache(znode)

  return data and true or false, err
end

function _M.delete_recursive(znode)
  local nodes, err = childrens(znode)
  if not nodes then
    return nil, err
  end

  for i=1,#nodes
  do
    local ok = delete_recursive(znode .. "/" .. nodes[i])
    if not ok then
      break
    end
  end

  return delete(znode)
end

function _M.tree(znode, with_stat)
  local data, err = zoo_call(function()
    return zoo.atree(znode)
  end)

  if not data then
    return nil, err
  end

  local tree = unpack(data)

  local function traverse(zpath, node)
    local value, stat = node.__value, node.__stat

    save_in_cache("$v", zpath, value, stat)
    node.__value, node.__stat = nil, nil

    local childs = {}

    for k,v in pairs(node)
    do
      table.insert(childs, k)
      if traverse(zpath .. "/" .. k, v) == 0 and not with_stat then
        node[k] = v.value
      end
    end

    save_in_cache("$c", zpath, childs, nil)

    node.value, node.stat = (#value ~= 0 or #childs == 0) and value or nil, with_stat and stat or nil

    return #childs
  end

  traverse(znode, tree)

  debug(function()
    return "zoo tree: ", znode, "=", json_encode(tree)
  end)

  return tree
end

function _M.connected()
  return zoo.connected()
end

local watched = {}
local job

function _M.unwatch(znode, watch_type)
  if watch_type ~= WatcherType.DATA and watch_type ~= WatcherType.CHILDREN then
    return nil, "invalid watch type"
  end

  local v = watched[znode]
  if not v or not v[watch_type] then
    return nil, "not watched (unwatch can be used only from ngx.timer context or when worker_processes=1)"
  end

  local ok, err = zoo_call(function()
    return zoo.aunwatch(znode, watch_type)
  end)

  if ok then
    watched[znode][watch_type] = nil

    debug(function()
      return "unwatch: ", znode, " type=", watch_type
    end)

    return true
  end

  return nil, err
end

function _M.watcher_exists(znode, watch_type)
  return watched[znode] ~= nil and (
    not watch_type or watched[znode][watch_type] == watch_type
  )
end

function _M.watch(znode, watch_type, callback, ctx)
  if watch_type ~= WatcherType.DATA and watch_type ~= WatcherType.CHILDREN then
    return nil, "invalid watch type"
  end

  local data, err = zoo_call(function()
    return zoo.awatch(znode, watch_type)
  end)

  if not data then
    if err == "awatch: exists" then
      if watch_type == WatcherType.DATA then
        data, err = zoo_call(function()
          return zoo.aget(znode)
        end)
      else
        data, err = zoo_call(function()
          return zoo.achildrens(znode)
        end)
      end
      if data then
        return data[1]
      end
    end
    return nil, err
  end

  debug(function()
    return "watch: ", znode, " type=", watch_type
  end)

  watched[znode] = watched[znode] or {}
  watched[znode][watch_type] = {
    callback = callback,
    ctx = ctx,
    path = znode
  }

  local result = data[1]

  if job then
    return result
  end

  local function handler(premature)
    if premature then
      return
    end

    job = nil

    local changed, err

    if not zoo.connected() then
      goto settimer
    end

    changed, err = zoo.changed()
 
    if not changed then
      ngx_log(WARN, "watch: ", err)
      goto settimer
    end

    if #changed ~= 0 then
      debug(function()
        return "changed: ", json_encode(changed)
      end)
    end

    for _,c in ipairs(changed)
    do
      local node, watcher_type = unpack(c)
      if watched[node] then
        local v = watched[node][watcher_type]
        if v then
          watched[node][watcher_type] = nil
          if not next(watched[node]) then
            watched[node] = nil
          end
          pcall(v.callback, v.ctx, {
            path = v.path,
            watcher_type = watcher_type
          })
        end
      end
    end

:: settimer ::

    job = assert(ngx.timer.at(zoo_watch_interval, handler))
  end

  job = assert(ngx.timer.at(zoo_watch_interval, handler))
  return result
end

function _M.watch_path(znode, callback, ctx)
  local tree = {}

  tree.__value = assert(watch(znode, WatcherType.DATA, callback, ctx))

  for _,c in ipairs(assert(watch(znode, WatcherType.CHILDREN, callback, ctx))) do
    tree[c] = assert(_M.watch_path(znode .. "/" .. c, callback, ctx))
  end

  return tree
end

do
  errors           = _M.errors
  WatcherType      = _M.WatcherType
  create           = _M.create
  delete           = _M.delete
  delete_recursive = _M.delete_recursive
  childrens        = _M.childrens
  watch            = _M.watch
  unwatch          = _M.unwatch
  clear_in_cache   = _M.clear_in_cache
end


return _M
