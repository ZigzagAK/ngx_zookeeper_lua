Name
====

ngx_zookeeper_lua - Lua bindings to interract with Zookeeper.

[![Build Status](https://drone.io/github.com/ZigzagAK/ngx_zookeeper_lua/status.png)](https://drone.io/github.com/ZigzagAK/ngx_zookeeper_lua/latest)

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
* [Configuration directives](#configuration-directives)
* [Base methods](#methods)
  * [connected](#connected)
  * [get](#get)
  * [childrens](#childrens)
  * [set](#set)
  * [create](#create)
  * [delete](#delete)
  * [delete_recursive](#delete_recursive)
* [Additional API](#additional-api)
  * [tree](#tree)
  * [import](#import)
* [Latest build](#latest-build)

Status
======

This library is production ready.

Description
===========

This module provides Lua bindings to interract with Zookeeper.

[Back to TOC](#table-of-contents)

Synopsis
========

```nginx
http {
  zookeeper              127.0.0.1:2181;
  zookeeper_log_level    debug;
  zookeeper_recv_timeout 5000;
  zookeeper_instances    /services/nginx 127.0.0.1:8080;

  lua_shared_dict config    64k;
  lua_shared_dict zoo_cache 10m;

  init_by_lua_block {
    ngx.shared.config:set("zoo.cache.on", true)
    ngx.shared.config:set("zoo.cache.ttl", 60)

    ngx.shared.config:set("zoo.cache.path.ttl", '[' ..
      '{ "path" : "/services/.*", "ttl" : 0 }' ..
   ']')
  }

  server {
    listen 4444;

    default_type application/json;

    server_name zoo;

    location = /get {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"

        local ok, value, err, stat = zoo.get(ngx.var.arg_znode)
        local r

        if ok then
          if not value then
            value = ""
          end
          r = { value = value, stat = stat }
        else
          r = { error = err }
        end

        ngx.say(cjson.encode(r))
      }
    }

    location = /childrens {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"

        local ok, childs, err = zoo.childrens(ngx.var.arg_znode)
        local r

        if ok then
          r = childs
        else
          r = { error = err }
        end

        ngx.say(cjson.encode(r))
      }
    }

    location = /set {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"

        local ok, err, stat = zoo.set(ngx.var.arg_znode, ngx.var.arg_value, ngx.var.arg_version)
        local r

        if ok then
          r = { value = ngx.var.arg_value, stat = stat }
        else
          r = { error = err }
        end

        ngx.say(cjson.encode(r))
      }
    }

    location = /create {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"

        local ok, r, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)

        if ok then
          r = { znode = r }
        else
          r = { error = err }
        end

        ngx.say(cjson.encode(r))
      }
    }

    location = /delete {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"

        local ok, err = zoo.delete(ngx.var.arg_znode)
        if ok then
          r = { znode = "deleted" }
        else
          r = { error = err }
        end

        ngx.say(cjson.encode(r))
      }
    }

    location = /tree {
      content_by_lua_block {
        local zoo = require 'zoo'

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

          if stat and ngx.var.arg_stat and ngx.var.arg_stat:match("[1yY]") then
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

        local cjson = require "cjson"

        ngx.say(cjson.encode(subtree(ngx.var.arg_znode)))
      }
    }
  }
}
```

[Back to TOC](#table-of-contents)

Configuration directives
========================

zookeeper
--------------
* **syntax**: `zookeeper <sever1:port,sever2:port,....>`
* **default**: `none`
* **context**: `http`

Configure Zookeeper servers.

zookeeper_log_level
--------------
* **syntax**: `zookeeper_log_level <number>`
* **default**: `error`
* **values**: `error, warn, info, debug`
* **context**: `http`

Configure Zookeeper log level.

zookeeper_recv_timeout
--------------
* **syntax**: `zookeeper_recv_timeout <number>`
* **default**: `10000`
* **values**: `1-60000`
* **context**: `http`

Configure Zookeeper socket recv timeout.

zookeeper_instances
--------------
* **syntax**: `zookeeper_instances <path/to/instances> <host:port>`
* **default**: `none`
* **context**: `http`

Register nginx in Zookeeper ethemeral node.

[Back to TOC](#table-of-contents)

Methods
=======

connected
---------
**syntax:** `connected = zoo.connected()`

**context:** *&#42;_by_lua&#42;*

Return status of Zookeeper connection.

Returns true or false.

get
---
**syntax:** `ok, value, err, stat = zoo.get(znode)`

**context:** *&#42;_by_lua&#42;*

Get value of the `znode` and znode information.
`stat`: { czxid, mzxid, ctime, mtime, version, cversion, aversion, ephemeralOwner, dataLength, numChildren, pzxid }

Returns true and value on success, or false and a string describing an error otherwise.

childrens
---------
**syntax:** `ok, childs, err = zoo.childrens(znode)`

**context:** *&#42;_by_lua&#42;*

Get child znode's names of the `znode`.

Returns true and table of names on success, or false and a string describing an error otherwise.

set
---
**syntax:** `ok, err, stat = zoo.set(znode, value, version)`

**context:** *&#42;_by_lua&#42;*

Set value of the `znode`. Version may be nil (no version check).
`stat`: { czxid, mzxid, ctime, mtime, version, cversion, aversion, ephemeralOwner, dataLength, numChildren, pzxid }

Returns true and znode information on success, or false and a string describing an error otherwise.

create
------
**syntax:** `ok, r, err = zoo.create(znode, value, mode)`

**context:** *&#42;_by_lua&#42;*

Create the `znode` with initial `value`.
`mode`: flags.ZOO_EPHEMERAL, flags.ZOO_SEQUENCE

Returns true and new `znode` path on success, or false and a string describing an error otherwise.

delete
------
**syntax:** `ok, err = zoo.delete(znode)`

**context:** *&#42;_by_lua&#42;*

Delete the `znode`.

Returns true on success, or false and a string describing an error otherwise.

[Back to TOC](#table-of-contents)

delete_recursive
----------------
**syntax:** `ok, err = zoo.delete_recursive(znode)`

**context:** *&#42;_by_lua&#42;*

Delete the `znode` with all childs.

Returns true on success, or false and a string describing an error otherwise.

[Back to TOC](#table-of-contents)

Additional API
==============

`local api = require "zoo.api"`

tree
----
**syntax:** `r = api.tree(znode, need_stat)`

**context:** *&#42;_by_lua&#42;*

Returns subtree of znode, or false and a string describing an error otherwise

import
------
**syntax:** `r = api.import(root, json)`

**context:** *&#42;_by_lua&#42;*

Import znodes from json (format - api.tree). Overwrite existing values.

Returns true on success, or false and a string describing an error otherwise.

# Latest build
  * https://drone.io/github.com/ZigzagAK/ngx_zookeeper_lua/files
