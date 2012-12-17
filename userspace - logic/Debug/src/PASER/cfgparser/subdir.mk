################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/PASER/cfgparser/PASER_cfgparser.cpp 

OBJS += \
./src/PASER/cfgparser/PASER_cfgparser.o 

CPP_DEPS += \
./src/PASER/cfgparser/PASER_cfgparser.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/cfgparser/%.o: ../src/PASER/cfgparser/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


