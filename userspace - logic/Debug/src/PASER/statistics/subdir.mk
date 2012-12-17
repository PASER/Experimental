################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/statistics/PASER_statistics.cc 

OBJS += \
./src/PASER/statistics/PASER_statistics.o 

CC_DEPS += \
./src/PASER/statistics/PASER_statistics.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/statistics/%.o: ../src/PASER/statistics/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


