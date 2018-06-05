#!/bin/bash

# Copyright, Aleksey Konovkin (alkon2000@mail.ru)
# BSD license type

if [ "$1" == "" ]; then
  echo "build.sh <clean/clean_all> <download/download_all> <build>"
  exit 0
fi

download=0
download_only=0
download_all=0
build_deps=0
clean_all=0
compile=0
build_only=0
make_clean=0

DIR="$(pwd)"
DIAG_DIR="diag"
VCS_PATH=${DIR%/*/*}

VERSION="1.13.6"
ZOO_VERSION="3.5.4-beta"
PCRE_VERSION="8.40"
LUAJIT_VERSION="2.1.0-beta2"
ZLIB_VERSION="1.2.11"

SUFFIX=""

if [ "$BUILD_DIR" == "" ]; then
  BUILD_DIR="$DIR/build"
fi

if [ "$INSTALL_DIR" == "" ]; then
  INSTALL_DIR="$DIR/install"
fi

if [ "$ERR_LOG" == "" ]; then
  ERR_LOG=/dev/null
else
  ERR_LOG=$BUILD_DIR/$ERR_LOG
fi

if [ "$BUILD_LOG" == "" ]; then
  BUILD_LOG=/dev/null
else
  BUILD_LOG=$BUILD_DIR/$BUILD_LOG
fi

[ -e "$BUILD_DIR" ] || mkdir -p $BUILD_DIR

export ZOO_PREFIX="$BUILD_DIR/deps/zookeeper"
export JIT_PREFIX="$BUILD_DIR/deps/luajit"
export ZLIB_PREFIX="$BUILD_DIR/deps/zlib"
export PCRE_PREFIX="$BUILD_DIR/deps/pcre"

export LUAJIT_INC="$JIT_PREFIX/usr/local/include/luajit-2.1"
export LUAJIT_LIB="$JIT_PREFIX/usr/local/lib"
export LUAJIT_BIN="$JIT_PREFIX/usr/local/bin/luajit-$LUAJIT_VERSION"

export LD_LIBRARY_PATH="-L$PCRE_PREFIX/lib:$LUAJIT_LIB:$ZOO_PREFIX/lib:$ZLIB_PREFIX/lib"

ADDITIONAL_INCLUDES="-I$PCRE_PREFIX/include -I$ZLIB_PREFIX/include"
ADDITIONAL_LIBS="-L$PCRE_PREFIX/lib -L$ZLIB_PREFIX/lib"

function clean() {
  rm -rf install  2>>$ERR_LOG
  if [ $clean_all -eq 1 ]; then
    rm -rf $BUILD_DIR  2>>$ERR_LOG
  else
    rm -rf $(ls -1d $BUILD_DIR/* 2>>$ERR_LOG | grep -v deps)    2>>$ERR_LOG
  fi
  if [ $download_all -eq 1 ]; then
    rm -rf src 2>>$ERR_LOG
  fi
}

doclean=0
dobuild=0

for i in "$@"
do
  if [ "$i" == "download" ]; then
    download=1
  fi

  if [ "$i" == "download_all" ]; then
    download=1
    download_all=1
  fi

  if [ "$i" == "clean_all" ]; then
    clean_all=1
    doclean=1
  fi

  if [ "$i" == "build" ]; then
    dobuild=1
  fi

  if [ "$i" == "build_only" ]; then
    dobuild=1
    build_only=1
  fi

  if [ "$i" == "clean" ]; then
    doclean=1
  fi

  if [ "$i" == "compile" ]; then
    compile=1
  fi
done

if [ $doclean -eq 1 ]; then
  clean
fi

if [ $download -eq 1 ] && [ $dobuild -eq 0 ]; then
  download_only=1
fi

if [ $download -eq 0 ] && [ $dobuild -eq 0 ]; then
    if [ $make_components -eq 0 ]; then 
      exit 0
    fi
fi


current_os=`uname`
if [ "$current_os" = "Linux" ]; then
  platform="linux"
  arch=`uname -p`
  shared="so"
  if [ -e /etc/redhat-release ]; then
    vendor='redhat'
    ver=`cat /etc/redhat-release | sed -e 's#[^0-9]##g' -e 's#7[0-2]#73#'`
    if [ $ver -lt 50 ]; then
      os_release='4.0'
    elif [ $ver -lt 60 ]; then
      os_release='5.0'
    elif [ $ver -lt 70 ]; then
      os_release='6.0'
    else
      os_release='7.0'
    fi
    if [ "$arch" != "x86_64" ]; then
      arch='i686'
    fi
    DISTR_NAME=$vendor-$platform-$os_release-$arch
  else
    vendor=$(uname -r)
    DISTR_NAME=$vendor-$platform-$arch
  fi
fi
if [ "$current_os" = "Darwin" ]; then
  platform="macos"
  arch=`uname -m`
  vendor="apple"
  shared="dylib"
  CFLAGS="-arch x86_64"
  DISTR_NAME=$vendor-$platform-$arch
fi

case $platform in
  linux)
    # platform has been recognized
    ;;
  macos)
    # platform has been recognized
    ;;
  *)
    echo "I do not recognize the platform '$platform'." | tee -a $BUILD_LOG
    exit 1;;
esac

if [ -z "$BUILD_VERSION" ]; then
    BUILD_VERSION="develop"
fi

function build_pcre() {
  echo "Build PCRE" | tee -a $BUILD_LOG
  cd pcre-$PCRE_VERSION
  ./configure --prefix="$PCRE_PREFIX" --libdir="$PCRE_PREFIX/lib" >> $BUILD_LOG 2>>$ERR_LOG
  make -j 8 >> $BUILD_LOG 2>>$ERR_LOG
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install >> $BUILD_LOG 2>>$ERR_LOG
  cd ..
}

function build_zlib() {
  echo "Build ZLIB" | tee -a $BUILD_LOG
  cd zlib-$ZLIB_VERSION
  ./configure --prefix="$ZLIB_PREFIX" --libdir="$ZLIB_PREFIX/lib" >> $BUILD_LOG 2>>$ERR_LOG
  make -j 8 >> $BUILD_LOG 2>>$ERR_LOG
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install >> $BUILD_LOG 2>>$ERR_LOG
  cd ..
}

function build_zoo() {
  echo "Build Zookeeper" | tee -a $BUILD_LOG
  cd zookeeper-$ZOO_VERSION/src/c
  ./configure --prefix="$ZOO_PREFIX" --enable-shared --disable-static --libdir "$ZOO_PREFIX/lib" >> $BUILD_LOG 2>>$ERR_LOG
  make -j 8 >> $BUILD_LOG 2>>$ERR_LOG
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install >> $BUILD_LOG 2>>$ERR_LOG
  cd ../../..
}

function build_luajit() {
  echo "Build luajit" | tee -a $BUILD_LOG
  cd LuaJIT-$LUAJIT_VERSION
  make >> $BUILD_LOG 2>>$ERR_LOG
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  DESTDIR="$JIT_PREFIX" make install >> $BUILD_LOG 2>>$ERR_LOG
  cd ..
}

function build_cJSON() {
  echo "Build cjson" | tee -a $BUILD_LOG
  cd lua-cjson
  LUA_INCLUDE_DIR="$JIT_PREFIX/usr/local/include/luajit-2.1" LDFLAGS="-L$JIT_PREFIX/usr/local/lib -lluajit-5.1" make >> $BUILD_LOG 2>>$ERR_LOG
  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  cd ..
}

function build_release() {
  cd nginx-$VERSION
  make clean >> $BUILD_LOG 2>>$ERR_LOG
  echo "Configuring release nginx-$VERSION" | tee -a $BUILD_LOG
  ./configure --prefix="$INSTALL_DIR/nginx-$VERSION" \
              $EMBEDDED_OPTS \
              --with-cc-opt="$ADDITIONAL_INCLUDES" \
              --with-ld-opt="$ADDITIONAL_LIBS" \
              --add-module=../ngx_devel_kit \
              --add-module=../lua-nginx-module \
              --add-module=../.. >> $BUILD_LOG 2>>$ERR_LOG

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi

  echo "Build release nginx-$VERSION" | tee -a $BUILD_LOG
  make -j 8 >> $BUILD_LOG 2>>$ERR_LOG

  r=$?
  if [ $r -ne 0 ]; then
    exit $r
  fi
  make install >> $BUILD_LOG 2>>$ERR_LOG
  cd ..
}

function gitclone() {
  LD_LIBRARY_PATH="" git clone $1 >> $BUILD_LOG 2> /tmp/err
  if [ $? -ne 0 ]; then
    cat /tmp/err
    exit 1
  fi
}

function gitcheckout() {
  git checkout $1 >> $BUILD_LOG 2> /tmp/err
  if [ $? -ne 0 ]; then
    cat /tmp/err
    exit 1
  fi
}

function download_module() {
  if [ $download -eq 1 ] || [ ! -e $3.tar.gz ]; then
    if [ $download_all -eq 1 ] || [ ! -e $3.tar.gz ]; then
      echo "Download $1/$2/$3.git from=$4" | tee -a $BUILD_LOG
      gitclone $1/$2/$3.git
      echo "$1/$2/$3.git" > $3.log
      echo >> $3.log
      cd $3
      gitcheckout $4
      echo $4" : "$(git log -1 --oneline | awk '{print $1}') >> ../$3.log
      echo >> ../$3.log
      git log -1 | grep -E "(^[Cc]ommit)|(^[Aa]uthor)|(^[Dd]ate)" >> ../$3.log
      cd ..
      tar zcf $3.tar.gz $3
      rm -rf $3
    else
      echo "Get $3" | tee -a $BUILD_LOG
    fi
  else
    echo "Get $3" | tee -a $BUILD_LOG
  fi
}

function download_dep() {
  if [ $download -eq 1 ] || [ ! -e $2-$3.tar.gz ]; then
    if [ $download_all -eq 1 ] || [ ! -e $2-$3.tar.gz ]; then
      echo "Download $2-$3.$4" | tee -a $BUILD_LOG
      LD_LIBRARY_PATH="" curl -s -L -o $2-$3.tar.gz $1/$2-$3.$4
      echo "$1/$2-$3.$4" > $2.log
    else
      echo "Get $2-$3.tar.gz" | tee -a $BUILD_LOG
    fi
  else
    echo "Get $2-$3.tar.gz" | tee -a $BUILD_LOG
  fi
}

function extract_downloads() {
  cd src

  for d in $(ls -1 *.tar.gz)
  do
    echo "Extracting $d" | tee -a $BUILD_LOG
    tar zxf $d -C $BUILD_DIR --keep-old-files 2>>$ERR_LOG
  done

  cd ..
}

function download() {
  mkdir -p $BUILD_DIR        2>>$ERR_LOG
  mkdir $BUILD_DIR/deps      2>>$ERR_LOG

  mkdir src             2>>$ERR_LOG
  mkdir src/lua_modules 2>>$ERR_LOG

  cd src

  download_dep http://nginx.org/download                                           nginx     $VERSION           tar.gz
  download_dep http://luajit.org/download                                          LuaJIT    $LUAJIT_VERSION    tar.gz
  download_dep http://www-us.apache.org/dist/zookeeper/zookeeper-$ZOO_VERSION      zookeeper $ZOO_VERSION       tar.gz
  download_dep http://ftp.cs.stanford.edu/pub/exim/pcre                            pcre      $PCRE_VERSION      tar.gz
  download_dep http://zlib.net                                                     zlib      $ZLIB_VERSION      tar.gz

  download_module https://github.com      simpl            ngx_devel_kit                    master
  download_module https://github.com      openresty        lua-nginx-module                 master
  download_module https://github.com      openresty        lua-cjson                        master

  cd ..
}

function install_file() {
  echo "Install $1" | tee -a $BUILD_LOG
  if [ ! -e "$INSTALL_DIR/nginx-$VERSION/$2" ]; then
    mkdir -p "$INSTALL_DIR/nginx-$VERSION/$2"
  fi
  if [ "$4" == "" ]; then
    if [ "$3" == "" ]; then
      cp -r $1 "$INSTALL_DIR/nginx-$VERSION/$2/"
    else
      cp -r $1 "$INSTALL_DIR/nginx-$VERSION/$2/$3"
    fi
  else
    echo $4 > "$INSTALL_DIR/nginx-$VERSION/$2/$3"
  fi
}

function install_gzip() {
  echo "Install $1" | tee -a $BUILD_LOG
  if [ ! -e "$INSTALL_DIR/nginx-$VERSION/$2" ]; then
    mkdir -p "$INSTALL_DIR/nginx-$VERSION/$2"
  fi
  if [ "$4" == "" ]; then
    if [ "$3" == "" ]; then
      tar zxf $1 -C "$INSTALL_DIR/nginx-$VERSION/$2/"
    else
      tar zxf $1 -C "$INSTALL_DIR/nginx-$VERSION/$2/$3"
    fi
  else
    echo $4 > "$INSTALL_DIR/nginx-$VERSION/$2/$3"
  fi
}

function install_files() {
  for f in $(ls $1)
  do
    install_file $f $2
  done
}

function build() {
  cd $BUILD_DIR

  if [ $build_only -eq 0 ]; then
    patch -N -p0 < $DIR/patches/lua-cjson-Makefile.patch
    patch -N -p0 < $DIR/patches/luajit.patch
  fi

  if [ $build_deps -eq 1 ] || [ ! -e deps/luajit ]; then
    build_luajit
  fi
  if [ $build_deps -eq 1 ] || [ ! -e deps/zookeeper ]; then
    build_zoo
  fi
  if [ $build_deps -eq 1 ] || [ ! -e deps/zlib ]; then
    build_zlib
  fi
  if [ $build_deps -eq 1 ] || [ ! -e deps/pcre ]; then
    build_pcre
  fi

  build_cJSON

  build_release

  install_file  "$JIT_PREFIX/usr/local/lib/*.$shared*"       lib
  install_file  "lua-cjson/cjson.so"                         lib/lua/5.1

  install_files "$ZOO_PREFIX/lib/libzookeeper_mt.$shared*"   lib

  install_files "$ZLIB_PREFIX/lib/libz.$shared*"             lib

  install_files "$PCRE_PREFIX/lib/libpcre.$shared*"          lib
  install_files "$PCRE_PREFIX/lib/libpcreposix.$shared*"     lib

  chmod 755 $INSTALL_DIR/nginx-$VERSION/lib/*.$shared*

  cd $DIR
}

if [ $build_only -eq 0 ]; then
  clean
fi
download
if [ $download_only -eq 0 ]; then
  if [ $build_only -eq 0 ]; then
    extract_downloads
  fi
  build
fi

function install_resty_module() {
  if [ $7 -eq 1 ] || [ ! -e $3.tar.gz ]; then
    if [ $8 -eq 1 ] || [ ! -e $3.tar.gz ]; then
      echo "Download $1/$2/$3.git from=$6" | tee -a $BUILD_LOG
      gitclone $1/$2/$3.git
      echo "$1/$2/$3.git" > $3.log
      echo >> $3.log
      cd $3
      gitcheckout $6
      echo $6" : "$(git log -1 --oneline | awk '{print $1}') >> ../$3.log
      echo >> ../$3.log
      git log -1 | grep -E "(^[Cc]ommit)|(^[Aa]uthor)|(^[Dd]ate)" >> ../$3.log
      cd ..
      tar zcf $3.tar.gz $3
      rm -rf $3
    else
      echo "Get $3-$6" | tee -a $BUILD_LOG
    fi
  else
    echo "Get $3-$6" | tee -a $BUILD_LOG
  fi
  if [ $9 -eq 0 ]; then
    echo "Install $3/$4" | tee -a $BUILD_LOG
    if [ ! -e "$INSTALL_DIR/nginx-$VERSION/$5" ]; then
      mkdir -p "$INSTALL_DIR/nginx-$VERSION/$5"
    fi
    if [ -e $3.tar.gz ]; then
      tar zxf $3.tar.gz
      cp -r $3/$4 "$INSTALL_DIR/nginx-$VERSION/$5/"
      rm -rf $3
    fi
  fi
}

uninstall_file() {
  rm -rf $INSTALL_DIR/nginx-$VERSION/$1
}

make_dir() {
  mkdir $INSTALL_DIR/nginx-$VERSION/$1
}

function install_lua_modules() {
  cd $DIR

  install_file conf .
  install_file html .
  install_file lua  .

  install_file scripts/start.sh   .
  install_file scripts/stop.sh    .
  install_file scripts/restart.sh .
}

install_lua_modules

cp LICENSE "$INSTALL_PREFIX/nginx-$VERSION$SUFFIX/LICENSE"

cd "$DIR"

kernel_name=$(uname -s)
kernel_version=$(uname -r)

cd install

tar zcvf nginx-$VERSION$SUFFIX-$kernel_name-$kernel_version.tar.gz nginx-$VERSION$SUFFIX
rm -rf nginx-$VERSION$SUFFIX

cd ..

exit $r
