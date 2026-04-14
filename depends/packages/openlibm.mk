package=openlibm
$(package)_version=0.8.7
$(package)_download_path=https://github.com/JuliaMath/openlibm/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=e328a1d59b94748b111e022bca6a9d2fc0481fb57d23c87d90f394b559d4f062

define $(package)_set_vars
  $(package)_build_opts=USEGCC=1 USECLANG=0
  $(package)_build_opts+=CC="$$($(package)_cc)"
  $(package)_build_opts+=AR="$$($(package)_ar)"
  $(package)_build_opts+=RANLIB="$$($(package)_ranlib)"
  $(package)_build_opts+=prefix=$(host_prefix)
  $(package)_build_opts_mingw32=OS=WINNT
endef

define $(package)_config_cmds
  true
endef

define $(package)_build_cmds
  $(MAKE) $($(package)_build_opts) libopenlibm.a
endef

define $(package)_stage_cmds
  $(MAKE) $($(package)_build_opts) DESTDIR=$($(package)_staging_dir) install-static install-headers
endef

define $(package)_postprocess_cmds
endef
