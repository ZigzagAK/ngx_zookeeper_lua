#!/bin/bash

# Copyright, Aleksey Konovkin (alkon2000@mail.ru)
# BSD license type

download=0
if [ "$1" == "1" ]; then
  download=1
fi
build_deps=1
build_debug=1
build_release=1

DIR="$(pwd)"

VERSION="1.11.6"
ZOO_VERSION="3.5.2-alpha"
PCRE_VERSION="8.39"
LUAJIT_VERSION="2.1.0-beta2"

SUFFIX="-zoo"

BASE_PREFIX="$DIR/build"
INSTALL_PREFIX="$DIR/install"

ZOO_PREFIX="$DIR/build/deps/zookeeper"
PCRE_PREFIX="$DIR/build/pcre-$PCRE_VERSION"
JIT_PREFIX="$DIR/build/deps/luajit"

export LUAJIT_INC="$JIT_PREFIX/usr/local/include/luajit-2.1"
export LUAJIT_LIB="$JIT_PREFIX/usr/local/lib"

export LD_LIBRARY_PATH="$JIT_PREFIX/lib:$ZOO_PREFIX/lib"

function clean() {
  rm -rf install  2>/dev/null
  if [ $download -eq 1 ]; then
    rm -rf build    2>/dev/null
    rm -rf download 2>/dev/null
  else
    if [ $build_debug -eq 1 ] && [ $build_release -eq 1 ]; then
      if [ -e build ]; then
        cd build
        if [ $build_deps -eq 1 ]; then
          rm -rf deps/* 2>/dev/null
        fi
        cd nginx-$VERSION                2>/dev/null && make clean > /dev/null 2>&1 ; cd $DIR/build
        cd LuaJIT-$LUAJIT_VERSION        2>/dev/null && make clean > /dev/null 2>&1 ; cd $DIR/build
        cd zookeeper-$ZOO_VERSION/src/c  2>/dev/null && make clean > /dev/null 2>&1 ; cd $DIR/build
        cd ..
      fi
    fi
  fi
}

if [ "$1" == "clean" ]; then
  clean
  exit 0
fi

function build_zoo() {
  echo "Build Zookeeper"
  cd zookeeper-$ZOO_VERSION/src/c
  ./configure --prefix="$ZOO_PREFIX" > /dev/null
  make -j 8 > /dev/null
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install > /dev/null
  cd ../../..
}

function build_luajit() {
  echo "Build luajit"
  cd LuaJIT-$LUAJIT_VERSION
  make -j 8 > /dev/null
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  DESTDIR="$JIT_PREFIX" make install > /dev/null
  cd ..
}

function build_debug() {
  cd nginx-$VERSION
  if [ $build_debug -eq 1 ] && [ $build_release -eq 1 ]; then
    echo "Configuring debug nginx-$VERSION$SUFFIX"
    ./configure --prefix="$INSTALL_PREFIX/nginx-$VERSION$SUFFIX" \
                --with-pcre=$PCRE_PREFIX \
                --with-stream \
                --with-debug \
                --with-cc-opt="-O0 -I$ZOO_PREFIX/include" \
                --with-ld-opt="-L$ZOO_PREFIX/lib -lzookeeper_mt" \
                --add-module=../ngx_devel_kit \
                --add-module=../lua-nginx-module \
                --add-module=../../../ngx_zookeeper_lua > /dev/null
  fi

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi

  echo "Build debug nginx-$VERSION$SUFFIX"
  make -j 8 > /dev/null

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install > /dev/null

  mv "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/sbin/nginx" "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/sbin/nginx.debug"
  cd ..
}

function build_release() {
  cd nginx-$VERSION
  echo "Configuring release nginx-$VERSION$SUFFIX"
  ./configure --prefix="$INSTALL_PREFIX/nginx-$VERSION$SUFFIX" \
              --with-pcre=$PCRE_PREFIX \
              --with-stream \
              --with-cc-opt="-I$ZOO_PREFIX/include" \
              --with-ld-opt="-L$ZOO_PREFIX/lib -lzookeeper_mt" \
              --add-module=../ngx_devel_kit \
              --add-module=../lua-nginx-module \
              --add-module=../../../ngx_zookeeper_lua > /dev/null

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi

  echo "Build release nginx-$VERSION$SUFFIX"
  make -j 8 > /dev/null

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install > /dev/null
  cd ..
}

function download_module() {
  echo "Download $2 branch=$3"
  rm -rf $2 $2-$3
  curl -s -L -O https://github.com/$1/$2/archive/$3.zip
  mv $3.zip $2-$3.zip
  unzip -q $2-$3.zip
  mv $2-$3 ../build/$2
}

function build_cJSON() {
  echo "Build cjson"
  cd lua-cjson
  PREFIX="$JIT_PREFIX/usr/local" make > /dev/null
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  cd ..
}

function download_nginx() {
  echo "Download nginx-$VERSION"
  curl -s -L -O http://nginx.org/download/nginx-$VERSION.tar.gz
  tar zxf nginx-$VERSION.tar.gz -C ../build
}

function download_luajit() {
  echo "Download LuaJIT-$LUAJIT_VERSION"
  curl -s -L -O http://luajit.org/download/LuaJIT-$LUAJIT_VERSION.tar.gz
  tar zxf LuaJIT-$LUAJIT_VERSION.tar.gz -C ../build
}

function download_zoo() {
  echo "Download Zookeeper-$ZOO_VERSION"
  curl -s -L -O http://www-eu.apache.org/dist/zookeeper/zookeeper-$ZOO_VERSION/zookeeper-$ZOO_VERSION.tar.gz
  tar zxf zookeeper-$ZOO_VERSION.tar.gz -C ../build
}

function download_pcre() {
  echo "Download PCRE-$PCRE_VERSION"
  curl -s -L -O http://ftp.cs.stanford.edu/pub/exim/pcre/pcre-$PCRE_VERSION.tar.gz
  tar zxf pcre-$PCRE_VERSION.tar.gz -C ../build
}

function download() {
  if [ $download -eq 0 ]; then
    return
  fi

  mkdir build                2>/dev/null
  mkdir build/debug          2>/dev/null
  mkdir build/deps           2>/dev/null

  mkdir download             2>/dev/null
  mkdir download/debug       2>/dev/null
  mkdir download/lua_modules 2>/dev/null

  cd download

  download_nginx
  download_luajit
  download_zoo
  download_pcre

  download_module simpl       ngx_devel_kit                    master
  download_module openresty   lua-nginx-module                 master
  download_module openresty   lua-cjson                        master

  cd ..
}

function install_file() {
  echo "Install $1"
  if [ ! -e "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$2" ]; then
    mkdir -p "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$2"
  fi
  cp -r $3 $1 "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$2/"
}

function install_files() {
  for f in $(ls $1)
  do
    install_file $f $2 $3
  done
}

function build() {
  cd build

  if [ $download -eq 1 ]; then
    patch -p0 < ../lua-cjson-Makefile.patch
  fi

  if [ $build_deps -eq 1 ]; then
    build_luajit
    build_cJSON
    build_zoo
  fi

  if [ $build_debug -eq 1 ]; then
    make clean > /dev/null 2>&1
    build_debug
  fi

  if [ $build_release -eq 1 ]; then
    make clean > /dev/null 2>&1
    build_release
  fi

  install_file  "$JIT_PREFIX/usr/local/lib"           .
  install_file  lua-cjson/cjson.so                    lib/lua/5.1
  install_files "$ZOO_PREFIX/lib/libzookeeper_mt.so*" lib

  cd ..
}

clean
download
build

function install_resty_module() {
  if [ $6 -eq 1 ]; then
    echo "Download $2 branch=$5"
    rm -rf $2-$5 2>/dev/null
    curl -s -L -O https://github.com/$1/$2/archive/$5.zip
    mv $5.zip $2-$5.zip
  fi
  echo "Install $2/$3"
  unzip -q $2-$5.zip
  if [ ! -e "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$4" ]; then
    mkdir -p "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$4"
  fi
  cp -r $2-$5/$3 "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/$4/"
  rm -rf $2-$5
}

function install_lua_modules() {
  if [ $download -eq 1 ]; then
    rm -rf download/lua_modules/* 2>/dev/null
  fi

  cd download/lua_modules

  install_resty_module openresty    lua-resty-core                      lib                .   master $download
  install_resty_module ZigzagAK     nginx-resty-auto-healthcheck-config scripts/start.sh   .   master $download
  install_resty_module ZigzagAK     nginx-resty-auto-healthcheck-config scripts/stop.sh    .   master 0
  install_resty_module ZigzagAK     nginx-resty-auto-healthcheck-config scripts/debug.sh   .   master 0
  install_resty_module ZigzagAK     nginx-resty-auto-healthcheck-config scripts/restart.sh .   master 0
  install_resty_module ZigzagAK     nginx-resty-auto-healthcheck-config lua/system.lua     lua master 0

  cd ../..

  install_file lua  .
  install_file conf .
  install_file html .
}

install_lua_modules

cp LICENSE "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/LICENSE"

cd "$DIR"

kernel_name=$(uname -s)
kernel_version=$(uname -r)

cd install
tar zcvf nginx-$VERSION$SUFFIX-$kernel_name-$kernel_version.tar.gz nginx-$VERSION$SUFFIX

gunzip -c nginx-$VERSION$SUFFIX-$kernel_name-$kernel_version.tar.gz | tar --list | sort | diff ../t/dist_content.txt -
r=$?
if [ $r -eq 0 ]; then
  rm -rf nginx-$VERSION$SUFFIX
else
  rm nginx-$VERSION$SUFFIX-$kernel_name-$kernel_version.tar.gz
fi

cd ..

exit $r