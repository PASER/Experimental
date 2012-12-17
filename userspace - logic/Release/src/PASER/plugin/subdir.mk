################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/PASER/plugin/PASER_plugin_loader.cpp \
../src/PASER/plugin/PASER_plugin_util.cpp 

OBJS += \
./src/PASER/plugin/PASER_plugin_loader.o \
./src/PASER/plugin/PASER_plugin_util.o 

CPP_DEPS += \
./src/PASER/plugin/PASER_plugin_loader.d \
./src/PASER/plugin/PASER_plugin_util.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/plugin/%.o: ../src/PASER/plugin/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


