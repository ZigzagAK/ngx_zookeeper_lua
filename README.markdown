Name
====

ngx_zookeeper_lua - Lua bindings to interract with Zookeeper.

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
* [Additional API](#additional-api)
  * [tree](#tree)
  * [import](#import)

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

Pre requirenments (for example centos/redhat)

```
sudo yum install gcc-c++.x86_64 zlib-devel openssl-devel
```

Build

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
  zookeeper_ethemeral_node /services/nginx 127.0.0.1;

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
    listen 8000;
    zookeeper_register_port /services/nginx/8000 8000;

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

zookeeper_ethemeral_node
--------------
* **syntax**: `zookeeper_ethemeral_node <path/to/instances> <value>`
* **default**: `none`
* **context**: `http,server,location`

Register nginx in Zookeeper ethemeral node.

zookeeper_register_port
--------------
* **syntax**: `zookeeper_register_port <path/to/instances> <port>`
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
**syntax:** `value, stat, err = zoo.get(znode)`

**context:** *&#42;_by_lua&#42;*

Get value of the `znode` and znode information.
`stat`: { czxid, mzxid, ctime, mtime, version, cversion, aversion, ephemeralOwner, dataLength, numChildren, pzxid }

Returns value on success, or nil and a string describing an error otherwise.

childrens
---------
**syntax:** `childs, err = zoo.childrens(znode)`

**context:** *&#42;_by_lua&#42;*

Get child znode's names of the `znode`.

Returns table with znode's names on success, or nil and a string describing an error otherwise.

set
---
**syntax:** `result, err = zoo.set(znode, value, version)`

**context:** *&#42;_by_lua&#42;*

Set value of the `znode`. Version may be nil (no version check).
`stat`: { czxid, mzxid, ctime, mtime, version, cversion, aversion, ephemeralOwner, dataLength, numChildren, pzxid }

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
