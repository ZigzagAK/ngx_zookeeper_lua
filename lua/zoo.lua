local zoo = require 'ngx.zookeeper'
local system = require "system"
local cjson = require "cjson"

local timeout = zoo.timeout()

local _M = {
  _VERSION = '1.0.0',

  errors = {
      ZOO_TIMEOUT = "TIMEOUT"
  },

  flags = {
      ZOO_EPHEMERAL = bit.lshift(1, 0),
      ZOO_SEQUENCE = bit.lshift(1, 1)
  }
}

local CACHE = ngx.shared.zoo_cache
local CONFIG = ngx.shared.config

local zoo_cache_on = CONFIG:get("zoo.cache.on") or true
local zoo_cache_ttl = CONFIG:get("zoo.cache.ttl") or 60
local zoo_cache_path_ttl = cjson.decode(CONFIG:get("zoo.cache.path.ttl") or {})

table.sort(zoo_cache_path_ttl, function(l, r) return #l.path > #r.path end)

local function get_ttl(znode)
  for _, z in ipairs(zoo_cache_path_ttl)
  do
    if znode:match(z.path) then
      return z.ttl
    end
  end
  return zoo_cache_ttl
end

local function timeto()
  ngx.update_time()
  return ngx.now() * 1000 + timeout
end

local function sleep(sec)
  local ok = pcall(ngx.sleep, sec)
  if not ok then
    ngx.log(ngx.WARN, "blocking sleep function is used")
    system.sleep(sec)
  end
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
    
  local cached = cjson.encode({ stat = stat, value = v })
    
  local ok, err, _ = CACHE:set(prefix .. ":" .. znode, cached, zoo_cache_ttl)

  if ok then
    ngx.log(ngx.DEBUG, "zoo set cached: ttl=" .. ttl .. "s," .. znode, "=", cached)
  else
    ngx.log(ngx.WARN, "zoo set cached: ", err)
  end
end

local function get_from_cache(prefix, znode)
  if not zoo_cache_on then
    return nil
  end

  local cached = CACHE:get(prefix .. ":" .. znode)
  
  if not cached then
    return nil
  end

  local r = cjson.decode(cached)

  ngx.log(ngx.DEBUG, "zoo get cached: ", znode, "=", cached)

  return r
end

function _M.get(znode)
  local cached = get_from_cache("v", znode)
  if cached then
    return true, cached.value, nil, cached.stat
  end

  local ok, sc = zoo.aget(znode)

  if not ok then
    return ok, nil, sc, nil
  end

  local time_limit = timeto()
  local completed, value, err, stat

  while not completed and ngx.now() * 1000 < time_limit
  do
    sleep(0.001)
    completed, value, err, stat = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  elseif not err then
    save_in_cache("v", znode, value, stat)
    ngx.log(ngx.DEBUG, "zoo get: ", znode, "=", value)
  end

  return completed and not err, value, err, stat
end

function _M.childrens(znode)
  local cached = get_from_cache("c", znode)
  if cached then
    return true, cached.value or {}, nil
  end

  local ok, sc = zoo.achildrens(znode)

  if not ok then
    return ok, nil, sc
  end

  local time_limit = timeto()
  local completed, childs, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    sleep(0.001)
    completed, childs, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  ok = completed and not err

  if ok then 
    save_in_cache("c", znode, childs, nil)
    ngx.log(ngx.DEBUG, "zoo get: ", znode, "=", cjson.encode(childs))
  end

  return ok, childs or {}, err
end

function _M.set(znode, value, version)
  if not version then
    version = -1
  end

  local ok, sc = zoo.aset(znode, value, version)

  if not ok then
    return ok, nil, sc, nil
  end

  local time_limit = timeto()
  local completed, err, stat

  while not completed and ngx.now() * 1000 < time_limit
  do
    sleep(0.001)
    completed, _, err, stat = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, err, stat
end

function _M.create(znode, value, flags)
  if not value then
    value = ""
  end

  if not flags then
    flags = 0
  end

  local ok, sc = zoo.acreate(znode, value, flags)

  if not ok then
    return ok, nil, sc
  end

  local time_limit = timeto()
  local completed, result, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    sleep(0.001)
    completed, result, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, result, err
end

function _M.create_path(znode)
  local path = "/"
  
  for p in znode:gmatch("/([^/]+)")
  do
    local ok, _, err = _M.create(path .. p)
    if not ok and err ~= "Znode already exists" then
      return ok, err
    end
    path = path .. p .. "/"
  end

  return true, nil
end

function _M.delete(znode)
  local ok, sc = zoo.adelete(znode)

  if not ok then
    return ok, sc
  end

  local time_limit = timeto()
  local completed, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    sleep(0.001)
    completed, _, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, err
end

function _M.delete_recursive(znode)
  local ok, nodes, err = _M.childrens(znode)
  if not ok then
    return ok, err
  end
  
  for _, node in ipairs(nodes)
  do
    ok, err = _M.delete_recursive(znode .. "/" .. node)
    if not ok then
      break
    end
  end

  return _M.delete(znode)
end

function _M.connected()
  return zoo.connected()
end

return _M
