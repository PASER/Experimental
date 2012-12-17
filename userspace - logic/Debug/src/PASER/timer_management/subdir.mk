################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/timer_management/PASER_timer_packet.cc \
../src/PASER/timer_management/PASER_timer_queue.cc 

OBJS += \
./src/PASER/timer_management/PASER_timer_packet.o \
./src/PASER/timer_management/PASER_timer_queue.o 

CC_DEPS += \
./src/PASER/timer_management/PASER_timer_packet.d \
./src/PASER/timer_management/PASER_timer_queue.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/timer_management/%.o: ../src/PASER/timer_management/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


