build-stamp:
clean:
install:
	@echo installing data to the dir: '$(DESTDIR)'
	if [ -z "$(DESTDIR)" ] ; then echo no DESTDIR >&1; exit 1 ; fi
	mkdir -p "$(DESTDIR)"/usr/lib/ruby/vendor_ruby/net/
	cp -a lib/net/ "$(DESTDIR)"/usr/lib/ruby/vendor_ruby/net/
