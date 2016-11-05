local zoo = require 'ngx.zookeeper'

local _M = {
  _VERSION = '0.99'
}

function _M.get(znode)
  local ok, sc = zoo.aget(znode)
  local r = nil

  if ok then
    ok, r = zoo.check_completition(sc)

    while not ok and r == nil
    do
      ngx.sleep(0.001)
      ok, r = zoo.check_completition(sc)
    end
  end

  return ok, r
end

return _M
