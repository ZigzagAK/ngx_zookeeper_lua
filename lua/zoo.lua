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
  _VERSION = "2.2.1",

  errors = {
    ZOO_TIMEOUT = "TIMEOUT"
  },

  flags = {
    ZOO_EPHEMERAL = bit.lshift(1, 0),
    ZOO_SEQUENCE = bit.lshift(1, 1)
  }
}

local errors
local create
local delete
local delete_recursive
local childrens
local clear_in_cache

local CACHE = ngx.shared.zoo_cache
local CONFIG = ngx.shared.config

local pcall, xpcall = pcall, xpcall
local ipairs = ipairs
local unpack = unpack
local type = type
local now, update_time = ngx.now, ngx.update_time
local ngx_log = ngx.log
local sleep = ngx.sleep
local WARN, DEBUG = ngx.WARN, ngx.DEBUG
local sub = string.sub
local rep = string.rep
local tconcat = table.concat

local json_decode = cjson.decode
local json_encode = cjson.encode

local zoo_cache_on = CONFIG:get("zoo.cache.on")
local zoo_cache_ttl = CONFIG:get("zoo.cache.ttl") or 60
local zoo_cache_path_ttl = json_decode(CONFIG:get("zoo.cache.path.ttl") or {})
local zoo_decode_json = CONFIG:get("zoo.decode_json")

local zoo_debug = CONFIG:get("zoo.cache.debug")
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
  CACHE:delete("c:" .. znode)
  CACHE:delete("v:" .. znode)
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

function _M.get(znode)
  local cached = get_from_cache("v", znode)
  if cached then
    return cached.value, cached.stat
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

  save_in_cache("v", znode, value or "", stat)

  return value or "", stat
end

function _M.childrens(znode)
  local cached = get_from_cache("c", znode)
  if cached then
    return cached.value or {}
  end

  local data, err = zoo_call(function()
    return zoo.achildrens(znode)
  end)

  if not data then
    return nil, err
  end

  local childs, stat = unpack(data)

  save_in_cache("c", znode, childs, nil)
  debug(function()
    return "zoo get: ", znode, "=", json_encode(childs)
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
  value = type(value) == "table" and json_encode(value) or value or ""

  local data, err = zoo_call(function()
    return zoo.acreate(znode, value, flags or 0)
  end)

  return data and (data[1] or "") or nil, err
end

function _M.create_path(znode)
  local path = "/"

  for p in znode:gmatch("/([^/]+)")
  do
    local ok, err = create(path .. p)
    if not ok and err ~= "Znode already exists" then
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

function _M.connected()
  return zoo.connected()
end

do
  errors           = _M.errors
  create           = _M.create
  delete           = _M.delete
  delete_recursive = _M.delete_recursive
  childrens        = _M.childrens
  clear_in_cache   = _M.clear_in_cache
end

return _M
