

# Any generated files must be added to this list (via +=) to be properly generated
# .. and the qapi-gen macro does this for you automatically
PLUGIN_GENERATED_FILES=

# qapi-gen macro for generating a QMP API
#
# Inputs:
# 	arg1: api name
# 	arg2: source directory (contains arg1.json)
# 	arg3: output directory
#
# Outputs:
# 	$(arg1)-interface-obj-y are the compiled objects
define qapi-gen

$(1)-interface-gen-c =  $(3)/$(1)-qapi-commands.c $(3)/$(1)-qapi-commands.h
$(1)-interface-gen-c += $(3)/$(1)-qapi-events.c $(3)/$(1)-qapi-events.h
$(1)-interface-gen-c += $(3)/$(1)-qapi-introspect.c $(3)/$(1)-qapi-introspect.h
$(1)-interface-gen-c += $(3)/$(1)-qapi-types.c $(3)/$(1)-qapi-types.h
$(1)-interface-gen-c += $(3)/$(1)-qapi-visit.c $(3)/$(1)-qapi-visit.h

$(1)-interface-obj-y =  $(3)/$(1)-qapi-commands.o
$(1)-interface-obj-y += $(3)/$(1)-qapi-events.o
$(1)-interface-obj-y += $(3)/$(1)-qapi-introspect.o
$(1)-interface-obj-y += $(3)/$(1)-qapi-types.o
$(1)-interface-obj-y += $(3)/$(1)-qapi-visit.o

$(3)/$(1)-gen-timestamp: $(2)
	$$(call quiet-command,$$(PYTHON) $$(SRC_PATH)/scripts/qapi-gen.py \
		-o $(3) -s -p $(1)- $$<, \
		"QAPI-GEN","$$(@:%-timestamp=%)")
	@>$$@

PLUGIN_GENERATED_FILES += $$($(1)-interface-gen-c)

$$($(1)-interface-gen-c): $(3)/$(1)-gen-timestamp

# These are inlined (instead of using implicit patterns) because of a bug
# in older versions of make

$(3)/$(1)-qapi-commands.o: $(3)/$(1)-qapi-commands.c $(3)/$(1)-qapi-commands.h
	$$(call quiet-command,$$(CC) -g -c $$(PLUGIN_CFLAGS) $$< -o $$@,"QAPI-CC","$$<")

$(3)/$(1)-qapi-events.o: $(3)/$(1)-qapi-events.c $(3)/$(1)-qapi-events.h
	$$(call quiet-command,$$(CC) -g -c $$(PLUGIN_CFLAGS) $$< -o $$@,"QAPI-CC","$$<")

$(3)/$(1)-qapi-introspect.o: $(3)/$(1)-qapi-introspect.c $(3)/$(1)-qapi-introspect.h
	$$(call quiet-command,$$(CC) -g -c $$(PLUGIN_CFLAGS) $$< -o $$@,"QAPI-CC","$$<")

$(3)/$(1)-qapi-types.o: $(3)/$(1)-qapi-types.c $(3)/$(1)-qapi-types.h
	$$(call quiet-command,$$(CC) -g -c $$(PLUGIN_CFLAGS) $$< -o $$@,"QAPI-CC","$$<")

$(3)/$(1)-qapi-visit.o: $(3)/$(1)-qapi-visit.c $(3)/$(1)-qapi-visit.h
	$$(call quiet-command,$$(CC) -g -c $$(PLUGIN_CFLAGS) $$< -o $$@,"QAPI-CC","$$<")

endef

