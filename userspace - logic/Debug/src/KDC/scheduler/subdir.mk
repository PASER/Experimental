################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/KDC/scheduler/KDCscheduler.cc \
../src/KDC/scheduler/KDCsocket.cc 

OBJS += \
./src/KDC/scheduler/KDCscheduler.o \
./src/KDC/scheduler/KDCsocket.o 

CC_DEPS += \
./src/KDC/scheduler/KDCscheduler.d \
./src/KDC/scheduler/KDCsocket.d 


# Each subdirectory must supply rules for building sources it contributes
src/KDC/scheduler/%.o: ../src/KDC/scheduler/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


