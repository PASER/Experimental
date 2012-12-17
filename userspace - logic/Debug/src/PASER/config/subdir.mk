################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/config/PASER_config.cc \
../src/PASER/config/PASER_global.cc 

OBJS += \
./src/PASER/config/PASER_config.o \
./src/PASER/config/PASER_global.o 

CC_DEPS += \
./src/PASER/config/PASER_config.d \
./src/PASER/config/PASER_global.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/config/%.o: ../src/PASER/config/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


