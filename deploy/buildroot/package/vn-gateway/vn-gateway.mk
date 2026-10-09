# Builds vn-gateway from the repository as a Buildroot package. VN_GATEWAY_SITE points at the
# checked-out source; set it with VN_GATEWAY_OVERRIDE_SRCDIR or edit here for your layout.
VN_GATEWAY_VERSION = 1.0
VN_GATEWAY_SITE_METHOD = local
VN_GATEWAY_SITE = $(BR2_EXTERNAL_VNSL_PATH)/../..
VN_GATEWAY_INSTALL_STAGING = NO
VN_GATEWAY_DEPENDENCIES =

define VN_GATEWAY_CONFIGURE_CMDS
	$(HOST_DIR)/bin/cmake -S $(@D) -B $(@D)/build-br -DCMAKE_BUILD_TYPE=Release -DVNSL_BUILD_TESTS=OFF \
		-DCMAKE_TOOLCHAIN_FILE=$(HOST_DIR)/share/buildroot/toolchainfile.cmake
endef
define VN_GATEWAY_BUILD_CMDS
	$(HOST_DIR)/bin/cmake --build $(@D)/build-br --target vn-gateway
endef
define VN_GATEWAY_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/build-br/vn-gateway $(TARGET_DIR)/usr/bin/vn-gateway
	$(INSTALL) -D -m 0644 $(BR2_EXTERNAL_VNSL_PATH)/../gateway.policy $(TARGET_DIR)/etc/vn-gateway/gateway.policy
endef
$(eval $(generic-package))
