use Test::Nginx::Socket;
use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: create & get & delete & get
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(path, " ", err)

          local val, _, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)

          ok, err = zoo.delete(ngx.var.arg_znode)
          ngx.say(ok, " ", err)

          local val, _, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test&value=test
--- response_body
/test nil
test nil
true nil
nil Znode does not exist


=== TEST 2: create failed
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          local ok, err = zoo.create(ngx.var.arg_znode)
          ngx.say(ok, " ", err)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test/no/node/found
--- response_body
nil Znode does not exist


=== TEST 3: create path & get
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local ok, err = zoo.create_path(ngx.var.arg_znode)
          ngx.say(ok, " ", err)

          local path, err = zoo.create(ngx.var.arg_znode .. "/0", ngx.var.arg_value)
          ngx.say(path, " ", err)

          local val, _, err = zoo.get(ngx.var.arg_znode .. "/0")
          ngx.say(val, " ", err)

          zoo.delete_recursive("/test")
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test/1/2/3&value=test
--- response_body
true nil
/test/1/2/3/0 nil
test nil


=== TEST 4: create & get & set & get & delete
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(path, " ", err)

          local val, _, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)

          local stat, err = zoo.set(ngx.var.arg_znode, ngx.var.arg_value2)
          ngx.say(stat ~= nil, " ", err)

          local val, _, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)

          zoo.delete_recursive(ngx.var.arg_znode)

          local val, _, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test&value=test&value2=test2
--- response_body
/test nil
test nil
true nil
test2 nil
nil Znode does not exist


=== TEST 5: create & childrens
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local ok, err = zoo.create(ngx.var.arg_znode)
          ngx.say(ok, " ", err)

          for i=1,5 do
            local path, err = zoo.create(ngx.var.arg_znode .. "/" .. i, i)
            ngx.say(path, " ", err)
          end

          local childrens, err = zoo.childrens(ngx.var.arg_znode)
          ngx.say(childrens ~= nil, " ", err)
          for _,c in ipairs(childrens or {})
          do
            local val, stat, err = zoo.get(ngx.var.arg_znode .. "/" .. c)
            ngx.say(val, " ", err)
          end

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test
--- response_body
/test nil
/test/1 nil
/test/2 nil
/test/3 nil
/test/4 nil
/test/5 nil
true nil
1 nil
2 nil
3 nil
4 nil
5 nil


=== TEST 6: create & tree
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          local cjson = require "cjson"

          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local ok, err = zoo.create(ngx.var.arg_znode)
          ngx.say(ok, " ", err)

          for i=1,3 do
            zoo.create(ngx.var.arg_znode .. "/" .. i, i)
            for j=11,13 do
              zoo.create(ngx.var.arg_znode .. "/" .. i .. "/" .. j, j)
            end
          end

          local tree, err = zoo.tree(ngx.var.arg_znode)
          ngx.say(tree ~= nil, " ", err)

          if tree ~= nil then
            ngx.say(cjson.encode(tree))
          end

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test
--- response_body
/test nil
true nil
{"1":{"12":"12","value":"1","11":"11","13":"13"},"2":{"12":"12","value":"2","11":"11","13":"13"},"3":{"12":"12","value":"3","11":"11","13":"13"}}


=== TEST 7: create & set cas
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          zoo.delete_recursive(ngx.var.arg_znode)

          local path, err = zoo.create(ngx.var.arg_znode, ngx.var.arg_value1)
          ngx.say(path, " ", err)

          local val, stat, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)

          local stat2, err = zoo.set(ngx.var.arg_znode, "***")
          ngx.say(stat2 ~= nil, " ", err)
          
          local s, err = zoo.set(ngx.var.arg_znode, ngx.var.arg_value2, stat.version)
          ngx.say(s == nil, " ", err)

          local s, err = zoo.set(ngx.var.arg_znode, ngx.var.arg_value2, stat2.version)
          ngx.say(s ~= nil, " ", err)

          local val, stat, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test&value1=test&value2=test2
--- response_body
/test nil
test nil
true nil
true Version conflict
true nil
test2 nil


=== TEST 7: create path
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
    }
--- config
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(0.5)

          local ok, err = zoo.create_path(ngx.var.arg_znode)
          ngx.say(ok, " ", err)

          local s, err = zoo.set(ngx.var.arg_znode, ngx.var.arg_value)
          ngx.say(s ~= nil, " ", err)

          local val, _, err = zoo.get(ngx.var.arg_znode)
          ngx.say(val, " ", err)

          zoo.delete_recursive(ngx.var.arg_znode)
        }
    }
--- timeout: 1
--- request
    GET /test?znode=/test/a/b/c/d/e&value=test
--- response_body
true nil
true nil
test nil

