SOURCES  = nn.hpp

CXXFLAGS = -x c++ -std=gnu++20 -Wno-pragma-once-outside-header
DEFINES  = -DATMOSPHERE -DATMOSPHERE_ARCH_ARM64 -DATMOSPHERE_BOARD_NINTENDO_NX -D__SWITCH__ \
           -DATMOSPHERE_OS_HORIZON -DATMOSPHERE_CPU_ARM_CORTEX_A57 -DATMOSPHERE_IS_STRATOSPHERE
INCLUDES = -I. -Ivapours

TARGETS = $(SOURCES:.hpp=.xml)

.PHONY: all clean

all: $(TARGETS)

%.xml: %.hpp
	@echo " CXX  " $@
	@castxml $(CXXFLAGS) $(DEFINES) $(INCLUDES) --castxml-gccxml $< -o $@

clean:
	@rm $(TARGETS) || :
