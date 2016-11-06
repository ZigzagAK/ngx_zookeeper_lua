local zoo = require 'ngx.zookeeper'

local timeout = zoo.timeout()

local _M = {
  _VERSION = '0.99',

  errors = {
      ZOO_TIMEOUT = "TIMEOUT"
  }
}

function _M.get(znode)
  local ok, sc = zoo.aget(znode)
  local time_limit = ngx.now() * 1000 + timeout

  if not ok then
    return ok, nil, sc
  end

  local completed = false
  local r, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, r, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return (completed and err == nil), r, err
end

function _M.childrens(znode)
  local ok, sc = zoo.achildrens(znode)
  local time_limit = ngx.now() * 1000 + timeout

  if not ok then
    return ok, nil, sc
  end

  local completed = false
  local r, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, r, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  ok = completed and err == nil
  if ok and r == nil then
    r = {}
  end

  return ok, r, err
end

function _M.set(znode, value)
  local ok, sc = zoo.aset(znode, value)
  local time_limit = ngx.now() * 1000 + timeout

  if not ok then
    return ok, nil, sc
  end

  local completed = false
  local err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return (completed and err == nil), err
end

function _M.create(znode, value)
  if value == nil then
    value = ""
  end

  local ok, sc = zoo.acreate(znode, value)
  local time_limit = ngx.now() * 1000 + timeout

  if not ok then
    return ok, nil, sc
  end

  local completed = false
  local r, err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, r, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return (completed and err == nil), r, err
end

function _M.delete(znode)
  local ok, sc = zoo.adelete(znode)
  local time_limit = ngx.now() * 1000 + timeout

  if not ok then
    return ok, nil, sc
  end

  local completed = false
  local err

  while not completed and ngx.now() * 1000 < time_limit
  do
    ngx.sleep(0.001)
    completed, _, err = zoo.check_completition(sc)
  end

  if not completed then
    zoo.forgot(sc)
    err = _M.errors.ZOO_TIMEOUT
  end

  return (completed and err == nil), err
end

return _M
