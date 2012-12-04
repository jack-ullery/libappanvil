#
PROVE=/usr/bin/prove
TESTS=simple.pl
PARSER_DIR=..
PARSER_BIN=apparmor_parser
PARSER=$(PARSER_DIR)/$(PARSER_BIN)
PROVE_ARG=-f

ifeq ($(VERBOSE),1)
  PROVE_ARG+=-v
endif

all: tests

.PHONY: tests error_output gen_xtrans parser_sanity caching minimize
tests: error_output gen_xtrans parser_sanity caching minimize

GEN_TRANS_DIRS=simple_tests/generated_x/ simple_tests/generated_perms_leading/ simple_tests/generated_perms_safe/

gen_xtrans: $(GEN_TRANS_DIRS)
	./gen-xtrans.pl

$(GEN_TRANS_DIRS):
	mkdir $@

error_output: $(PARSER)
	$(PARSER) -S -I errors >/dev/null errors/okay.sd
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/single.sd | \
		grep -q "AppArmor parser error for errors/single.sd in errors/single.sd at line 3: Could not open 'failure'"
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/double.sd | \
		grep -q "AppArmor parser error for errors/double.sd in errors/includes/busted at line 66: Could not open 'does-not-exist'"
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/modefail.sd | \
		grep -q "AppArmor parser error for errors/modefail.sd in errors/modefail.sd at line 6: syntax error"
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/multi_include.sd | \
		grep -q "AppArmor parser error for errors/multi_include.sd in errors/multi_include.sd at line 12: Could not open 'failure'"
	@echo "Error Output: PASS"

parser_sanity: $(PARSER)
	$(Q)LANG=C APPARMOR_PARSER="$(PARSER)" ${PROVE} ${PROVE_ARG} ${TESTS}

caching: $(PARSER)
	LANG=C APPARMOR_PARSER="$(PARSER)" ./caching.sh

minimize: $(PARSER)
	LANG=C APPARMOR_PARSER="$(PARSER)" ./minimize.sh

$(PARSER):
	make -C $(PARSER_DIR) $(PARSER_BIN)

clean:
	find $(GEN_TRANS_DIRS) -type f | xargs rm -f
