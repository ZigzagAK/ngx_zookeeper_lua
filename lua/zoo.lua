local zoo = require 'ngx.zookeeper'

local timeout = zoo.timeout()

local _M = {
  _VERSION = '0.99',

  errors = {
      ZOO_TIMEOUT = "TIMEOUT"
  }
}

local function timeto()
  return ngx.now() * 1000 + timeout
end

function _M.get(znode)
  local ok, sc = zoo.aget(znode)
  
  if not ok then
    return ok, nil, sc
  end

  local time_limit = timeto()
  local completed, value, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, value, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, value, err
end

function _M.childrens(znode)
  local ok, sc = zoo.achildrens(znode)

  if not ok then
    return ok, nil, sc
  end

  local time_limit = timeto()
  local completed, childs, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, childs, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  ok = completed and not err

  if ok and not childs then
    childs = {}
  end

  return ok, childs, err
end

function _M.set(znode, value)
  local ok, sc = zoo.aset(znode, value)
  
  if not ok then
    return ok, nil, sc
  end

  local time_limit = timeto()
  local completed, err
  
  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, err
end

function _M.create(znode, value)
  if not value then
    value = ""
  end

  local ok, sc = zoo.acreate(znode, value)
  
  if not ok then
    return ok, nil, sc
  end

  local time_limit = timeto()
  local completed, result, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, result, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, result, err
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
    ngx.sleep(0.001)
    completed, _, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return completed and not err, err
end

return _M
