
.PHONY: all prepare build test clean resolvtest resolvprepare remove

all: prepare build


prepare:
	if [ ! -d mruby ]; then git clone git@github.com:mruby/mruby.git ./mruby; fi

build:
	cd mruby; MRUBY_CONFIG=../misc/build_config.rb ./minirake; cd ..

test:
	cd mruby; MRUBY_CONFIG=../misc/build_config.rb ./minirake test; cd ..





resolvprepare:

resolvtest:

clean:
	cd mruby; ./minirake clean; cd ..

remove:
	rm -rf mruby
