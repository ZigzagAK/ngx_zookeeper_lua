use Test::Nginx::Socket;
use Test::Nginx::Socket::Lua::Stream;

$ENV{TEST_NGINX_ZOOKEEPER_PORT} ||= 2181;

repeat_each(1);

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__


=== TEST 1: Test 1
--- http_config
    lua_load_resty_core off;
    lua_package_path          "lua/?.lua;;";

    zookeeper                 127.0.0.1:$TEST_NGINX_ZOOKEEPER_PORT;
    zookeeper_log_level       debug;
    zookeeper_recv_timeout    60000;
    zookeeper_inactive_time   1;

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

          zoo.delete_recursive("/test")

          for i=1,5 do
            local ok, err = zoo.create("/test", tostring(i))
            if not ok then
              ngx.say(err)
              return
            end

            ngx.sleep(2)

            local val, _, err = zoo.get("/test")
            if not val then
              ngx.say(err)
              return
            end

            ngx.say(val)

            zoo.delete_recursive("/test")

            ngx.sleep(2)
          end
        }
    }
--- timeout: 25
--- request
    GET /test
--- response_body_like
1
2
3
4
5
