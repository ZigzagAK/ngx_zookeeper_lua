local _M = {
  _VERSION = "1.0.0"
}

local zoo = require "zoo"

function _M.get(znode)
  local ok, value, err, stat = zoo.get(znode)
  local r

  if ok then
    if not value then
      value = ""
    end
    r = { value = value, stat = stat }
  else
    r = { error = err }
  end

  return r
end

function _M.childrens(znode)
  local ok, childs, err = zoo.childrens(znode)
  local r

  if ok then
    r = childs
  else
    r = { error = err }
  end

  return r
end

function _M.set(znode, value, version)
  local ok, err, stat = zoo.set(znode, value, version)
  local r

  if ok then
    r = { value = ngx.var.arg_value, stat = stat }
  else
    r = { error = err }
  end

  return r
end

function _M.create(znode, value)
  local ok, r, err = zoo.create(znode, value)

  if ok then
    r = { znode = r }
  else
    r = { error = err }
  end

  return r
end

function _M.delete(znode)
  local ok, err = zoo.delete(ngx.var.arg_znode)
  local r
  
  if ok then
    r = { znode = "deleted" }
  else
    r = { error = err }
  end

  return r
end

function _M.tree(znode, need_stat)
  local subtree

  subtree = function(znode)
    local ok, value, err, stat = zoo.get(znode)
    if not ok then
      error(err)
    end

    if not value then
      value = ""
    end

    local tree = { value = value }

    if need_stat and stat then
      tree.stat = stat
    end

    if stat and stat.numChildren == 0 then
      return tree
    end

    local ok, childs, err = zoo.childrens(znode)
    if not ok then
      error(err)
    end

    if not znode:match("/$") then
      znode = znode .. "/"
    end

    for _, child in pairs(childs)
    do
      tree[child] = subtree(znode .. child)
    end

    return tree
  end
  
  return subtree(znode)
end

return _M