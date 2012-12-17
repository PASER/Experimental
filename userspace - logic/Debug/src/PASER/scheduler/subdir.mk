################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/scheduler/PASER_scheduler.cc 

OBJS += \
./src/PASER/scheduler/PASER_scheduler.o 

CC_DEPS += \
./src/PASER/scheduler/PASER_scheduler.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/scheduler/%.o: ../src/PASER/scheduler/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


