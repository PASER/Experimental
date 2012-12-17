################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/paser_socket/PASER_socket.cc \
../src/PASER/paser_socket/rom_client.cc 

OBJS += \
./src/PASER/paser_socket/PASER_socket.o \
./src/PASER/paser_socket/rom_client.o 

CC_DEPS += \
./src/PASER/paser_socket/PASER_socket.d \
./src/PASER/paser_socket/rom_client.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/paser_socket/%.o: ../src/PASER/paser_socket/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


