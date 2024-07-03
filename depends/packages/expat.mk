package=expat
$(package)_version=2.6.2
$(package)_download_path=http://sourceforge.net/projects/expat/files/expat/$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=d4cf38d26e21a56654ffe4acd9cd5481164619626802328506a2869afab29ab3

define $(package)_set_vars
$(package)_config_opts=--disable-static
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
