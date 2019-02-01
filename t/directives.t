use Test::Nginx::Socket;
use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: Persistent node
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
    zookeeper_node /test node data;
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(3)

          local val, stat, err = zoo.get("/test/node")
          if not val then
            ngx.say(err)
            return
          end
          ngx.say(val, " ", stat.ephemeralOwner == 0)

          zoo.delete_recursive("/test")
        }
    }
--- timeout: 4
--- request
    GET /test
--- response_body
data true


=== TEST 2: Ethemeral node
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
    zookeeper_ethemeral_node /test node data;
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(3)

          local val, stat, err = zoo.get("/test/node")
          if not val then
            ngx.say(err)
            return
          end
          ngx.say(val, " ", stat.ephemeralOwner ~= 0)

          zoo.delete_recursive("/test")
        }
    }
--- timeout: 4
--- request
    GET /test
--- response_body
data true


=== TEST 3: Register port
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
    zookeeper_register_port /test 8888 data;
    location /test {
        content_by_lua_block {
          local zoo = require "zoo"
          ngx.sleep(3)

          local nodes, err = zoo.childrens("/test")
          if not nodes then
            ngx.say(err)
            return
          end

          for _,node in ipairs(nodes) do
            local val, stat, err = zoo.get("/test/" .. node)
            if not val then
              ngx.say(err)
              return
            end
            ngx.say(node:match(":(%d+)$"), " ", val, " ", stat.ephemeralOwner ~= 0)
          end

          zoo.delete_recursive("/test")
        }
    }
--- timeout: 4
--- request
    GET /test
--- response_body_like
8888 data true

