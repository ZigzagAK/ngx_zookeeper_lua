local _M = {
  _VERSION = "2.0.0"
}

local zoo = require "zoo"

function _M.get(znode)
  local value, stat, err = zoo.get(znode)
  return value and { value = value, stat = stat } or { error = err }
end

function _M.childrens(znode)
  local childs, err = zoo.childrens(znode)
  return childs and childs or { error = err }
end

function _M.set(znode, value, version)
  local stat, err = zoo.set(znode, value, version)
  return stat and { value = ngx.var.arg_value, stat = stat } or { error = err }
end

function _M.create(znode, value)
  local result, err = zoo.create(znode, value)
  return result and { znode = result } or { error = err }
end

function _M.delete(znode, recursive)
  local ok, err

  if recursive and recursive:match("[Yy1]") then
    ok, err = zoo.delete_recursive(znode)
  else
    ok, err = zoo.delete(znode)
  end

  return ok and { znode = "deleted" } or { error = err }
end

function _M.tree(znode, need_stat)
  local subtree

  subtree = function(znode)
    local value, stat, err = zoo.get(znode)
    if not value then
      error(err)
    end

    local tree = {}

    if need_stat and stat then
      tree = { value = value,
               stat  = stat }
    end

    if stat and stat.numChildren == 0 then
      return value
    end

    if #value ~= 0 then
      tree.value = value
    end

    local childs, err = zoo.childrens(znode)
    if not childs then
      error(err)
    end

    if not znode:match("/$") then
      znode = znode .. "/"
    end

    for _, child in pairs(childs)
    do
      local ok, r = pcall(subtree, znode .. child)
      if not ok then
        zoo.clear_in_cache(znode .. child)
        r = subtree(znode .. child)
      end
      tree[child] = r
    end

    return tree
  end

  local ok, r = pcall(subtree, znode)

  if not ok then
    zoo.clear_in_cache(znode)
    ok, r = pcall(subtree, znode)
  end

  if not ok then
    r = { error = r }
  end

  return r
end

function _M.import(root, json)
  local cjson = require "cjson"

  local create_in_depth = function(zoo_path)
    local ok, err = zoo.create_path(zoo_path)
    if not ok then
      error(err)
    end
  end

  local set = function(path, value)
    ngx.log(ngx.DEBUG, "zoo import: set znode=" .. path .. ", value=" .. value)
    local ok, err = zoo.set(path, value)
    if not ok then
      error(err)
    end
  end

  local save_subtree
  save_subtree = function(path, subtree)
    for k, v in pairs(subtree)
    do
      if k ~= "value" and k ~= "stat" then
        local znode_path = path .. "/" .. k
        create_in_depth(znode_path)
        if type(v) == "table" then
          if v.value then
            set(znode_path, v.value)
          end
          save_subtree(znode_path, v)
        else
          set(znode_path, v)
        end
      end
    end
  end

  local ok, err = pcall(create_in_depth, root)
  if not ok then
    return ok, err
  end

  return pcall(save_subtree, root, cjson.decode(json))
end

return _M
