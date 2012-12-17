################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/packet_processing/PASER_blacklist.cc \
../src/PASER/packet_processing/PASER_packet_processing.cc \
../src/PASER/packet_processing/PASER_packet_sender.cc 

OBJS += \
./src/PASER/packet_processing/PASER_blacklist.o \
./src/PASER/packet_processing/PASER_packet_processing.o \
./src/PASER/packet_processing/PASER_packet_sender.o 

CC_DEPS += \
./src/PASER/packet_processing/PASER_blacklist.d \
./src/PASER/packet_processing/PASER_packet_processing.d \
./src/PASER/packet_processing/PASER_packet_sender.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/packet_processing/%.o: ../src/PASER/packet_processing/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


