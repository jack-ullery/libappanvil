#
PROVE=/usr/bin/prove
TESTS=simple.pl
PARSER_DIR=..
PARSER_BIN=apparmor_parser
PARSER=$(PARSER_DIR)/$(PARSER_BIN)

ifeq ($(VERBOSE),1)
  PROVE_ARG=-v
endif

all: tests

.PHONY: tests error_output parser_sanity caching
tests: error_output parser_sanity caching

error_output: $(PARSER)
	$(PARSER) -S -I errors >/dev/null errors/okay.sd
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/single.sd | \
		grep -q "AppArmor parser error for errors/single.sd in errors/single.sd at line 3: Could not open 'failure'"
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/double.sd | \
		grep -q "AppArmor parser error for errors/double.sd in errors/includes/busted at line 67: Could not open 'does-not-exist'"
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/modefail.sd | \
		grep -q "AppArmor parser error for errors/modefail.sd in errors/modefail.sd at line 6: syntax error"
	LANG=C $(PARSER) -S -I errors 2>&1 >/dev/null errors/multi_include.sd | \
		grep -q "AppArmor parser error for errors/multi_include.sd in errors/multi_include.sd at line 12: Could not open 'failure'"
	@echo "Error Output: PASS"

parser_sanity: $(PARSER)
	$(Q)${PROVE} ${PROVE_ARG} ${TESTS}

caching: $(PARSER)
	LANG=C ./caching.sh

$(PARSER):
	make -C $(PARSER_DIR) $(PARSER_BIN)
