################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/syslog/PASER_syslog.cc 

OBJS += \
./src/PASER/syslog/PASER_syslog.o 

CC_DEPS += \
./src/PASER/syslog/PASER_syslog.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/syslog/%.o: ../src/PASER/syslog/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


