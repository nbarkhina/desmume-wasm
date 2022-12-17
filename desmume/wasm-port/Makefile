MAKEFLAGS += --no-builtin-rules

CFILES :=   ../src/libretro-common/encodings/encoding_utf.c

CPPFILES := main.cpp \
  ../src/wifi.cpp \
  ../src/armcpu.cpp \
  ../src/cp15.cpp \
  ../src/firmware.cpp \
  ../src/MMU.cpp \
  ../src/readwrite.cpp \
  ../src/SPU.cpp \
  ../src/arm_instructions.cpp \
  ../src/Database.cpp \
  ../src/gfx3d.cpp \
  ../src/movie.cpp \
  ../src/render3D.cpp \
  ../src/texcache.cpp \
  ../src/arm_jit.cpp \
  ../src/debug.cpp \
  ../src/GPU.cpp \
  ../src/NDSSystem.cpp \
  ../src/ROMReader.cpp \
  ../src/thumb_instructions.cpp \
  ../src/bios.cpp \
  ../src/driver.cpp \
   ../src/rtc.cpp \
  ../src/version.cpp \
  ../src/cheatSystem.cpp \
  ../src/emufile.cpp \
  ../src/matrix.cpp \
  ../src/saves.cpp \
  ../src/commandline.cpp \
  ../src/encrypt.cpp \
  ../src/mc.cpp \
  ../src/path.cpp \
  ../src/slot1.cpp \
  ../src/common.cpp \
  ../src/FIFO.cpp \
  ../src/mic.cpp \
  ../src/rasterize.cpp \
  ../src/slot2.cpp \
  ../src/utils/xstring.cpp  \
  ../src/metaspu/metaspu.cpp  \
  ../src/utils/guid.cpp  \
  ../src/addons/slot1_none.cpp  \
  ../src/addons/slot1_retail_auto.cpp  \
  ../src/addons/slot1_retail_nand.cpp   \
  ../src/addons/slot1_retail_mcrom.cpp   \
  ../src/addons/slot1comp_mc.cpp  \
  ../src/addons/slot2_none.cpp  \
  ../src/utils/colorspacehandler/colorspacehandler.cpp  \
  ../src/addons/slot1comp_rom.cpp  \
  ../src/addons/slot1comp_protocol.cpp  \
  ../src/utils/datetime.cpp  \
  ../src/utils/decrypt/decrypt.cpp  \
  ../src/utils/decrypt/header.cpp   \
  ../src/filter/xbrz.cpp  \
  ../src/filter/deposterize.cpp


FILES := $(patsubst %.c,%.o,$(CFILES)) $(patsubst %.cpp,%.o,$(CPPFILES))

MYFLAGS := \
	-DHAVE_LIBZ \
	-I../src \
	-I../src/libretro-common/include \
	-I../src/utils \
	-I../src/metaspu \
	-I. \
	-flto -O3 -sUSE_ZLIB=1

COMPILEFLAGS := \
    -O3 --emit-symbol-map -s USE_ZLIB=1 \
	-sEXPORTED_FUNCTIONS=['_savGetPointer','_savUpdateChangeFlag','_savGetSize','_fillAudioBuffer','_runFrame','_main','_getSymbol','_prepareRomBuffer','_loadROM']  \
	-sEXPORT_ALL=1 -sTOTAL_MEMORY=629145600 -sLLD_REPORT_UNDEFINED

all: cleandata main.js

main.js: $(FILES)
	emcc -o $@ $(FILES) \
    $(COMPILEFLAGS)

%.o : %.cpp
	emcc -c $< -o $@ \
	$(MYFLAGS)

%.o : %.c
	emcc -c $< -o $@ \
	$(MYFLAGS)

clean:
	@echo "Cleaning"
	@echo $(FILES)
	rm -fr *.o */*.o */*/*.o */*/*/*.o */*/*/*/*.o

cleandata:
	@echo "Cleaning data"
	rm -fr *.data