################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/route_discovery/PASER_route_discovery.cc 

OBJS += \
./src/PASER/route_discovery/PASER_route_discovery.o 

CC_DEPS += \
./src/PASER/route_discovery/PASER_route_discovery.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/route_discovery/%.o: ../src/PASER/route_discovery/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


