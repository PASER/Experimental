################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/packet_structure/PASER_B_ROOT.cc \
../src/PASER/packet_structure/PASER_GTKREP.cc \
../src/PASER/packet_structure/PASER_GTKREQ.cc \
../src/PASER/packet_structure/PASER_GTKRESET.cc \
../src/PASER/packet_structure/PASER_MSG.cc \
../src/PASER/packet_structure/PASER_RESET.cc \
../src/PASER/packet_structure/PASER_TB_HELLO.cc \
../src/PASER/packet_structure/PASER_TB_RERR.cc \
../src/PASER/packet_structure/PASER_TU_RREP.cc \
../src/PASER/packet_structure/PASER_TU_RREP_ACK.cc \
../src/PASER/packet_structure/PASER_TU_RREQ.cc \
../src/PASER/packet_structure/PASER_UB_RREQ.cc \
../src/PASER/packet_structure/PASER_UU_RREP.cc 

OBJS += \
./src/PASER/packet_structure/PASER_B_ROOT.o \
./src/PASER/packet_structure/PASER_GTKREP.o \
./src/PASER/packet_structure/PASER_GTKREQ.o \
./src/PASER/packet_structure/PASER_GTKRESET.o \
./src/PASER/packet_structure/PASER_MSG.o \
./src/PASER/packet_structure/PASER_RESET.o \
./src/PASER/packet_structure/PASER_TB_HELLO.o \
./src/PASER/packet_structure/PASER_TB_RERR.o \
./src/PASER/packet_structure/PASER_TU_RREP.o \
./src/PASER/packet_structure/PASER_TU_RREP_ACK.o \
./src/PASER/packet_structure/PASER_TU_RREQ.o \
./src/PASER/packet_structure/PASER_UB_RREQ.o \
./src/PASER/packet_structure/PASER_UU_RREP.o 

CC_DEPS += \
./src/PASER/packet_structure/PASER_B_ROOT.d \
./src/PASER/packet_structure/PASER_GTKREP.d \
./src/PASER/packet_structure/PASER_GTKREQ.d \
./src/PASER/packet_structure/PASER_GTKRESET.d \
./src/PASER/packet_structure/PASER_MSG.d \
./src/PASER/packet_structure/PASER_RESET.d \
./src/PASER/packet_structure/PASER_TB_HELLO.d \
./src/PASER/packet_structure/PASER_TB_RERR.d \
./src/PASER/packet_structure/PASER_TU_RREP.d \
./src/PASER/packet_structure/PASER_TU_RREP_ACK.d \
./src/PASER/packet_structure/PASER_TU_RREQ.d \
./src/PASER/packet_structure/PASER_UB_RREQ.d \
./src/PASER/packet_structure/PASER_UU_RREP.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/packet_structure/%.o: ../src/PASER/packet_structure/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


