Name
====

ngx_zookeeper_lua - Lua bindings to interract with Zookeeper.

Build status
============
[![Build Status](https://travis-ci.org/ZigzagAK/ngx_zookeeper_lua.svg)](https://travis-ci.org/ZigzagAK/ngx_zookeeper_lua)

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
* [Install](#install)
* [Simple UI](#simple-ui)
* [Configuration directives](#configuration-directives)
* [Base methods](#methods)
  * [connected](#connected)
  * [get](#get)
  * [childrens](#childrens)
  * [set](#set)
  * [create](#create)
  * [delete](#delete)
  * [delete_recursive](#delete_recursive)
  * [tree](#tree)
  * [watch](#watch)
  * [watch_path](#watch_path)
  * [watcher_exists](#watcher_exists)
  * [unwatch](#unwatch)
* [Additional API](#additional-api)
  * [api.tree](#api-tree)
  * [api.import](#api-import)

Status
======

This library is production ready.

Description
===========

This module provides Lua bindings to interract with Zookeeper.

[Back to TOC](#table-of-contents)

Install
=======

Build nginx with Zookeeper support.
All dependencies are downloaded automaticaly.

```
git clone git@github.com:ZigzagAK/ngx_zookeeper_lua.git
cd ngx_zookeeper_lua
./build.sh
```

Archive will be placed in the `install` folder after successful build.

[Back to TOC](#table-of-contents)

Synopsis
========

```nginx
http {
  zookeeper                127.0.0.1:2181;
  zookeeper_log_level      debug;
  zookeeper_recv_timeout   5000;
  zookeeper_ethemeral_node /services/nginx 127.0.0.1 "nginx";

  lua_shared_dict config    64k;
  lua_shared_dict zoo_cache 10m;

  init_by_lua_block {
    ngx.shared.config:set("zoo.cache.on", true)
    ngx.shared.config:set("zoo.cache.ttl", 60)

    ngx.shared.config:set("zoo.cache.path.ttl", '[' ..
      '{ "path" : "/services/.*", "ttl" : 0 }' ..
   ']')
  }

  init_worker_by_lua_block {
    assert(ngx.timer.at(1, function()
      local zoo = require "zoo"
      local cjson = require "cjson"

      zoo.delete_recursive("/watched1")
      zoo.delete_recursive("/watched2")

      zoo.create("/watched1")
      zoo.create("/watched2")

      local function on_event(ctx)
        local data = assert(zoo.watch(ctx.path, ctx.watcher_type, on_event, ctx))
        ngx.log(ngx.INFO, "on_event: ", ctx.path, "=", cjson.encode(data))
      end

      on_event {
        watcher_type = zoo.WatcherType.DATA,
        path = "/watched1"
      }

      on_event {
        watcher_type = zoo.WatcherType.DATA,
        path = "/watched2"
      }

      on_event {
        watcher_type = zoo.WatcherType.CHILDREN,
        path = "/watched1"
      }

      on_event {
        watcher_type = zoo.WatcherType.CHILDREN,
        path = "/watched2"
      }

      local stop

      assert(ngx.timer.at(60, function()
        assert(zoo.unwatch("/watched1", zoo.WatcherType.DATA))
        assert(zoo.unwatch("/watched1", zoo.WatcherType.CHILDREN))
        assert(zoo.unwatch("/watched2", zoo.WatcherType.DATA))
        assert(zoo.unwatch("/watched2", zoo.WatcherType.CHILDREN))
        ngx.log(ngx.INFO, "unwatch")
        stop = ngx.now() + 10
      end))

      local i = 0

      local function change(premature)
        if premature or (stop and stop < ngx.now()) then
          return
        end

        pcall(function()
          if zoo.connected() then
            i = i + 1

            assert(zoo.set("/watched1", i))
            assert(zoo.set("/watched2", i))

            if i % 2 == 1 then
              assert(zoo.create("/watched1/1"))
              assert(zoo.create("/watched2/1"))
            else
              assert(zoo.delete("/watched1/1"))
              assert(zoo.delete("/watched2/1"))
            end

            ngx.log(ngx.INFO, "update")
          end
        end)

        assert(ngx.timer.at(1, change))
      end

      assert(ngx.timer.at(1, change))
    end))
  }

  server {
    listen 8000;
    zookeeper_register_port /services/nginx/8000 8000 "nginx-8080";

    location / {
      return 200 '8000';
    }
  }

  server {
    listen 8001;

    location /a {
      zookeeper_ethemeral_node /services/nginx/8001/a 127.0.0.1:8001;
      return 200 '8001:a';
    }

    location /b {
      zookeeper_ethemeral_node /services/nginx/8001/b 127.0.0.1:8001;
      return 200 '8001:b';
    }
  }

  server {
    listen 12181;

    include mime.types;
    default_type application/json;

    root html/zoo;

    index index.html;

    server_name zoo;

    location = /get {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"
        local value, stat, err = zoo.get(ngx.var.arg_znode)
        ngx.say(cjson.encode(value and { value = value, stat = stat } or { error = err }))
      }
    }

    location = /childrens {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"
        local childs, err = zoo.childrens(ngx.var.arg_znode)
        ngx.say(cjson.encode(childs and childs or { error = err }))
      }
    }

    location = /set {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"
        local stat, err = zoo.set(ngx.var.arg_znode, ngx.var.arg_value, ngx.var.arg_version)
        ngx.say(cjson.encode(stat and { value = ngx.var.arg_value, stat = stat } or { error = err }))
      }
    }

    location = /create {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"
        local result, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
        ngx.say(cjson.encode(result and { znode = result } or { error = err }))
      }
    }

    location = /delete {
      content_by_lua_block {
        local zoo = require "zoo"
        local cjson = require "cjson"
        local ok, err = zoo.delete(ngx.var.arg_znode)
        ngx.say(cjson.encode(ok and { znode = "deleted" } or { error = err }))
      }
    }

    location = /tree {
      content_by_lua_block {
        local api = require "zoo.api"
        local cjson = require "cjson"
        ngx.say(cjson.encode(api.tree(ngx.var.arg_znode,
                                      ngx.var.arg_stat and ngx.var.arg_stat:match("[1yY]"))))
      }
    }

    location = /import {
      content_by_lua_block {
        local api = require "zoo.api"

        local method = ngx.req.get_method()
        if method ~= "POST" and method ~= "PUT" then
          ngx.exit(ngx.HTTP_BAD_REQUEST)
        end

        local content_type = ngx.req.get_headers().content_type

        if not content_type or content_type:lower() ~= "application/json" then
          ngx.exit(ngx.HTTP_BAD_REQUEST)
        end

        ngx.req.read_body()
        local data = ngx.req.get_body_data()

        local ok, err = api.import(ngx.var.arg_znode or "/", data)
        if ok then
          ngx.say("Imported")
        else
          ngx.say(err)
        end
      }
    }
  }
}
```

**Watch tree**

```nginx
  location / {
    content_by_lua_block {
      local zoo = require "zoo"
      local cjson = require "cjson"

      local function on_event(ctx, ev)
        local data = assert(zoo.watch(ev.path, ev.watcher_type, on_event, ctx))
        ngx.log(ngx.INFO, "on_event: ", ev.path, ", type=", ev.watcher_type, " :", cjson.encode(data))
        if ev.watcher_type == zoo.WatcherType.CHILDREN then
          for _,c in ipairs(data) do
            if not zoo.watcher_exists(ev.path .. "/" .. c) then
              assert(zoo.watch_path(ev.path .. "/" .. c, on_event, ctx))
            end
          end
          ctx.data[ev.path] = data
        end
      end

      local ctx = { ["/test"] = assert(zoo.childrens("/test")) }
      assert(zoo.watch_path("/test", on_event, ctx))
    }
  }
```

[Back to TOC](#table-of-contents)

Simple UI
========================
UI displays Zookeeper content.
Available on `http://127.0.0.1:4444`

![UI](zoo_ui.png)

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

zookeeper_node
--------------
* **syntax**: `zookeeper_node <path/to/node> <node> [data]`
* **default**: `none`
* **context**: `http,server,location`

Create persistent Zookeeper node.

zookeeper_ethemeral_node
--------------
* **syntax**: `zookeeper_ethemeral_node <path/to/instances> <value> [data]`
* **default**: `none`
* **context**: `http,server,location`

Register nginx in Zookeeper ethemeral node.

zookeeper_register_port
--------------
* **syntax**: `zookeeper_register_port <path/to/instances> <port> [data]`
* **default**: `none`
* **context**: `server`

Register nginx in Zookeeper ethemeral node with host_IPv4:port.

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
**syntax:** `value, stat, err = zoo.get(znode, nocache)`

**context:** *&#42;_by_lua&#42;*

Get value of the `znode` and znode information.
`stat`: { czxid, mzxid, ctime, mtime, version, cversion, aversion, ephemeralOwner, dataLength, numChildren, pzxid }  

`nocache=true`: bypass cache.  

Returns value on success, or nil and a string describing an error otherwise.

childrens
---------
**syntax:** `childs, err = zoo.childrens(znode, nocache)`

**context:** *&#42;_by_lua&#42;*

Get child znode's names of the `znode`.  

`nocache=true`: bypass cache. 

Returns table with znode's names on success, or nil and a string describing an error otherwise.

set
---
**syntax:** `result, err = zoo.set(znode, value, version)`

**context:** *&#42;_by_lua&#42;*

Set value of the `znode`. Version may be nil (no version check). `value` may be a table (converted to json on store).

Returns znode information on success, or nil and a string describing an error otherwise.

create
------
**syntax:** `result, err = zoo.create(znode, value, mode)`

**context:** *&#42;_by_lua&#42;*

Create the `znode` with initial `value`.
`mode`: flags.ZOO_EPHEMERAL, flags.ZOO_SEQUENCE

Returns new `znode` path on success, or nil and a string describing an error otherwise.

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

tree
----
**syntax:** `data, err = zoo.tree(znode, need_stat)`

**context:** *&#42;_by_lua&#42;*

Returns subtree of znode, or false and a string describing an error otherwise

watch
----------------
**syntax:** `data, err = zoo.watch(znode, watch_type, callback, ctx)`

**context:** *&#42;_by_lua&#42;*

Get value or childrens and setup wather for `znode`.  

watcher_type MUST be one of `zoo.WatcherType.CHILDREN, zoo.WatcherType.DATA`.  

Returns value/childrens on success, or nil and a string describing an error otherwise.  

See [Synopsis](#synopsis) for details.

[Back to TOC](#table-of-contents)

watch_path
----------------
**syntax:** `tree, err = zoo.watch_path(znode, callback, ctx)`

**context:** *&#42;_by_lua&#42;*

Get full tree and setup watchers whole tree.  

Return tree on success, or nil and a string describing an error otherwise.  

See [Synopsis](#synopsis) for details.

[Back to TOC](#table-of-contents)

watcher_exists
----------------
**syntax:** `flag = zoo.watcher_exists(znode, watch_type)`

**context:** *&#42;_by_lua&#42;*

Check for watcher exists for `znode`.  

watcher_type MUST be one of `zoo.WatcherType.CHILDREN, zoo.WatcherType.DATA` or MAY be nil.  

Returns true or false.  

See [Synopsis](#synopsis) for details.

[Back to TOC](#table-of-contents)

unwatch
----------------
**syntax:** `data, err = zoo.unwatch(znode, watch_type)`

**context:** *&#42;_by_lua&#42;*

Remove watcher for `znode`.

watcher_type MUST be one of `zoo.WatcherType.CHILDREN, zoo.WatcherType.DATA`.  

Returns true on success, or nil and a string describing an error otherwise.  

See [Synopsis](#synopsis) for details.

[Back to TOC](#table-of-contents)

Additional API
==============

`local api = require "zoo.api"`

api tree
--------
**syntax:** `r = api.tree(znode, need_stat)`

**context:** *&#42;_by_lua&#42;*

Returns subtree of znode, or false and a string describing an error otherwise

api import
----------
**syntax:** `r = api.import(root, json)`

**context:** *&#42;_by_lua&#42;*

Import znodes from json (format - api.tree). Overwrite existing values.

Returns true on success, or false and a string describing an error otherwise.
