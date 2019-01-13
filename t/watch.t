use Test::Nginx::Socket;
use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: data watch
--- http_config
    lua_package_path          "lua/?.lua;;";

    zookeeper                 127.0.0.1:2181;
    zookeeper_log_level       debug;
    zookeeper_recv_timeout    60000;

    lua_shared_dict config    64k;
    lua_shared_dict zoo_cache 10m;

    init_by_lua_block {
      ngx.shared.config:set("zoo.cache.on", false)
      ngx.shared.config:set("zoo.cache.path.ttl", "{}")
      ngx.shared.config:set("zoo.watch.interval", 0.1)
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(path, " ", err)

          local t = {}

          local function on_event(ctx)
            local data = assert(zoo.watch(ctx.path, ctx.watcher_type, on_event, ctx))
            table.insert(t, data)
          end

          on_event {
            watcher_type = zoo.WatcherType.DATA,
            path = ngx.var.arg_znode
          }

          for j=1,3 do
            ngx.sleep(1)
            local s, err = zoo.set(ngx.var.arg_znode, j)
            ngx.say(s ~= nil, " ", err)
          end

          ngx.sleep(1)

          local ok, err = zoo.unwatch(ngx.var.arg_znode, zoo.WatcherType.DATA)
          ngx.say("unwatch:", ok, " ", err)

          for _,v in ipairs(t) do
            ngx.say(v)
          end

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 6
--- request
    GET /test?znode=/test&value=0
--- response_body
/test nil
true nil
true nil
true nil
unwatch:true nil
0
1
2
3


=== TEST 2: data watch (delete)
--- http_config
    lua_package_path          "lua/?.lua;;";

    zookeeper                 127.0.0.1:2181;
    zookeeper_log_level       debug;
    zookeeper_recv_timeout    60000;

    lua_shared_dict config    64k;
    lua_shared_dict zoo_cache 10m;

    init_by_lua_block {
      ngx.shared.config:set("zoo.cache.on", false)
      ngx.shared.config:set("zoo.cache.path.ttl", "{}")
      ngx.shared.config:set("zoo.watch.interval", 0.1)
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(path, " ", err)

          local t = {}

          local function on_event(ctx)
            local data, err = zoo.watch(ctx.path, ctx.watcher_type, on_event, ctx)
            table.insert(t, data or err)
          end

          on_event {
            watcher_type = zoo.WatcherType.DATA,
            path = ngx.var.arg_znode
          }

          for j=1,3 do
            ngx.sleep(1)
            local s, err = zoo.set(ngx.var.arg_znode, j)
            ngx.say(s ~= nil, " ", err)
          end

          ngx.sleep(1)

          local ok, err = zoo.delete(ngx.var.arg_znode)
          ngx.say("deleted:", ok, " ", err)

          ngx.sleep(1)

          for _,v in ipairs(t) do
            ngx.say(v)
          end

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 7
--- request
    GET /test?znode=/test&value=0
--- response_body
/test nil
true nil
true nil
true nil
deleted:true nil
0
1
2
3
Znode does not exist


=== TEST 3: childrens watch
--- http_config
    lua_package_path          "lua/?.lua;;";

    zookeeper                 127.0.0.1:2181;
    zookeeper_log_level       debug;
    zookeeper_recv_timeout    60000;

    lua_shared_dict config    64k;
    lua_shared_dict zoo_cache 10m;

    init_by_lua_block {
      ngx.shared.config:set("zoo.cache.on", false)
      ngx.shared.config:set("zoo.cache.path.ttl", "{}")
      ngx.shared.config:set("zoo.watch.interval", 0.1)
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(path, " ", err)

          local t = {}

          local function on_event(ctx)
            local data = assert(zoo.watch(ctx.path, ctx.watcher_type, on_event, ctx))
            table.insert(t, data)
          end

          on_event {
            watcher_type = zoo.WatcherType.CHILDREN,
            path = ngx.var.arg_znode
          }

          for j=1,3 do
            ngx.sleep(1)
            local path, err = zoo.create(ngx.var.arg_znode .. "/" .. j)
            ngx.say(path, " ", err)
          end

          ngx.sleep(1)

          local ok, err = zoo.unwatch(ngx.var.arg_znode, zoo.WatcherType.CHILDREN)
          ngx.say("unwatch:", ok, " ", err)

          for _,v in ipairs(t) do
            for _,c in ipairs(v) do
              ngx.print(c)
            end
            ngx.say()
          end

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 6
--- request
    GET /test?znode=/test&value=0
--- response_body_like
/test nil
/test/1 nil
/test/2 nil
/test/3 nil
unwatch:true nil

1
12
123


=== TEST 3: childrens watch (delete)
--- http_config
    lua_package_path          "lua/?.lua;;";

    zookeeper                 127.0.0.1:2181;
    zookeeper_log_level       debug;
    zookeeper_recv_timeout    60000;

    lua_shared_dict config    64k;
    lua_shared_dict zoo_cache 10m;

    init_by_lua_block {
      ngx.shared.config:set("zoo.cache.on", false)
      ngx.shared.config:set("zoo.cache.path.ttl", "{}")
      ngx.shared.config:set("zoo.watch.interval", 0.1)
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(path, " ", err)

          local t = {}

          local function on_event(ctx)
            local data, err = zoo.watch(ctx.path, ctx.watcher_type, on_event, ctx)
            table.insert(t, data or { err })
          end

          on_event {
            watcher_type = zoo.WatcherType.CHILDREN,
            path = ngx.var.arg_znode
          }

          for j=1,3 do
            ngx.sleep(1)
            local path, err = zoo.create(ngx.var.arg_znode .. "/" .. j)
            ngx.say(path, " ", err)
          end

          ngx.sleep(1)

          for j=1,3 do
            local ok, err = zoo.delete(ngx.var.arg_znode .. "/" .. j)
            ngx.say("delete:", ok, " ", err)
          end

          ngx.sleep(1)

          local ok, err = zoo.delete(ngx.var.arg_znode)
          ngx.say("delete node:", ok, " ", err)

          ngx.sleep(1)

          for _,v in ipairs(t) do
            ngx.print(#v .. ":")
            for _,c in ipairs(v) do
              ngx.print(c)
            end
            ngx.say()
          end
        }
    }
--- timeout: 10
--- request
    GET /test?znode=/test&value=0
--- response_body
/test nil
/test/1 nil
/test/2 nil
/test/3 nil
delete:true nil
delete:true nil
delete:true nil
delete node:true nil
0:
1:1
2:12
3:123
0:
1:Znode does not exist

