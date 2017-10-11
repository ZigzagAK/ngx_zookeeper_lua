local zoo = require 'ngx.zookeeper'
local system = require "system"
local cjson = require "cjson"

local timeout = zoo.timeout()

local _M = {
  _VERSION = '2.0.0',

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

local function get_expires()
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

  local ok, err = CACHE:set(prefix .. ":" .. znode, cached, zoo_cache_ttl)

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

  ngx.log(ngx.DEBUG, "zoo get cached: ", znode, "=", cached)

  return cjson.decode(cached)
end

function _M.get(znode)
  local cached = get_from_cache("v", znode)
  if cached then
    return cached.value, cached.stat
  end

  local sc, err = zoo.aget(znode)
  if not sc then
    return nil, nil, err
  end

  local expires = get_expires()
  local completed, value, err, stat

  while not completed and ngx.now() * 1000 < expires
  do
    sleep(0.001)
    completed, value, err, stat = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    return nil, nil, errors.ZOO_TIMEOUT
  end

  if err then
    return nil, nil, err
  end

  save_in_cache("v", znode, value or "", stat)
  ngx.log(ngx.DEBUG, "zoo get: ", znode, "=", value)

  return value or "", stat
end

function _M.childrens(znode)
  local cached = get_from_cache("c", znode)
  if cached then
    return cached.value or {}
  end

  local sc, err = zoo.achildrens(znode)
  if not sc then
    return nil, err
  end

  local expires = get_expires()
  local completed, childs, err

  while not completed and ngx.now() * 1000 < expires
  do
    sleep(0.001)
    completed, childs, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    return nil, errors.ZOO_TIMEOUT
  end

  if err then
    return nil, err
  end

  save_in_cache("c", znode, childs, nil)
  ngx.log(ngx.DEBUG, "zoo get: ", znode, "=", cjson.encode(childs))

  return childs or {}
end

function _M.set(znode, value, version)
  local sc, err = zoo.aset(znode, value, version or -1)
  if not sc then
    return nil, err
  end

  local expires = get_expires()
  local completed, void, err, stat

  while not completed and ngx.now() * 1000 < expires
  do
    sleep(0.001)
    completed, void, err, stat = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    return nil, errors.ZOO_TIMEOUT
  end

  return stat, err
end

function _M.create(znode, value, flags)
  local sc, err = zoo.acreate(znode, value or "", flags or 0)
  if not sc then
    return nil, err
  end

  local expires = get_expires()
  local completed, result, err

  while not completed and ngx.now() * 1000 < expires
  do
    sleep(0.001)
    completed, result, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    return nil, errors.ZOO_TIMEOUT
  end

  if err then
    return nil, err
  end

  return result or "", err
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

  return true, nil
end

function _M.delete(znode)
  local sc, err = zoo.adelete(znode)
  if not sc then
    return nil, err
  end

  local expires = get_expires()
  local completed, void, err

  while not completed and ngx.now() * 1000 < expires
  do
    sleep(0.001)
    completed, void, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    return nil, errors.ZOO_TIMEOUT
  end

  return not err, err
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
  errors = _M.errors
  create = _M.create
  delete = _M.delete
  delete_recursive = _M.delete_recursive
  childrens = _M.childrens
end

return _M
