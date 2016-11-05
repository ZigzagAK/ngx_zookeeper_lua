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
  local r = nil

  if ok then
    ok, r = zoo.check_completition(sc)

    while not ok and r == nil and ngx.now() * 1000 < time_limit
    do
      ngx.sleep(0.001)
      ok, r = zoo.check_completition(sc)
    end
  end

   if not ok and ngx.now() * 1000 >= time_limit then
      zoo.forgot(sc)
      r = ZOO_TIMEOUT
   end

  return ok, r
end

return _M
