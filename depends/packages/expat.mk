package=expat
$(package)_version=2.6.2
$(package)_download_path=hhttps://github.com/libexpat/libexpat/releases/download/R_2_6_2/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=461ecc8aa98ab1a68c2db788175665d1a4db640dc05bf0e289b6ea17122144ec

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
