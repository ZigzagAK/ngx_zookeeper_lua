Name
====

ngx_zookeeper_lua - Lua bindings to interract with Zookeeper.

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
* [Configuration directives](#configuration-directives)
* [Methods](#methods)
  * [get](#get)
  * [childrens](#childrens)
  * [set](#set)
  * [create](#create)
  * [delete](#delete)

Status
======

This library is still under early development.

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

  server {
    listen 4444;

    location = /get {
      content_by_lua_block {
          local zoo = require 'zoo'
          local ok, value, err = zoo.get(ngx.var.arg_znode)
          if ok then
            ngx.say(value)
          else
            ngx.say(err)
          end
      }
    }

    location = /childrens {
      content_by_lua_block {
          local zoo = require 'zoo'
          local ok, childs, err = zoo.childrens(ngx.var.arg_znode)
          if ok then
            for _, child in pairs(childs)
            do
              ngx.say(child)
            end
          else
            ngx.say(err)
          end
      }
    }

    location = /set {
      content_by_lua_block {
          local zoo = require 'zoo'
          local ok, err = zoo.set(ngx.var.arg_znode, ngx.var.arg_value)
          if ok then
            ngx.say("Stored")
          else
            ngx.say(err)
          end
      }
    }

    location = /create {
      content_by_lua_block {
          local zoo = require 'zoo'
          local ok, r, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          if ok then
            ngx.say(r)
          else
            ngx.say("ERR:" .. err)
          end
      }
    }

    location = /delete {
      content_by_lua_block {
          local zoo = require 'zoo'
          local ok, err = zoo.delete(ngx.var.arg_znode)
          if ok then
            ngx.say("Deleted")
          else
            ngx.say(err)
          end
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

[Back to TOC](#table-of-contents)

Methods
=======

get
-------------
**syntax:** `ok, value, err = zoo.get(znode)`

**context:** *&#42;_by_lua&#42;*

Get value of the `znode`.

Returns true and value on success, or false and a string describing an error otherwise.

childrens
-------------
**syntax:** `ok, childs, err = zoo.childrens(znode)`

**context:** *&#42;_by_lua&#42;*

Get child znode's names of the `znode`.

Returns true and table of names on success, or false and a string describing an error otherwise.

set
-------------
**syntax:** `ok, err = zoo.set(znode, value)`

**context:** *&#42;_by_lua&#42;*

Set value of the `znode`.

Returns true on success, or false and a string describing an error otherwise.

create
-------------
**syntax:** `ok, r, err = zoo.create(znode, value)`

**context:** *&#42;_by_lua&#42;*

Create the `znode` with initial `value`.

Returns true and new `znode` path on success, or false and a string describing an error otherwise.

delete
-------------
**syntax:** `ok, err = zoo.delete(znode)`

**context:** *&#42;_by_lua&#42;*

Delete the `znode`.

Returns true on success, or false and a string describing an error otherwise.

[Back to TOC](#table-of-contents)
