################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/KDC/config/KDCconfig.cc 

OBJS += \
./src/KDC/config/KDCconfig.o 

CC_DEPS += \
./src/KDC/config/KDCconfig.d 


# Each subdirectory must supply rules for building sources it contributes
src/KDC/config/%.o: ../src/KDC/config/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


