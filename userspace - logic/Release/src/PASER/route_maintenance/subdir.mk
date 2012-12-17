################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/route_maintenance/PASER_route_maintenance.cc 

OBJS += \
./src/PASER/route_maintenance/PASER_route_maintenance.o 

CC_DEPS += \
./src/PASER/route_maintenance/PASER_route_maintenance.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/route_maintenance/%.o: ../src/PASER/route_maintenance/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


