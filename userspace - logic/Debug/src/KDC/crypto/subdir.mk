################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/KDC/crypto/KDCcryptosign.cc 

OBJS += \
./src/KDC/crypto/KDCcryptosign.o 

CC_DEPS += \
./src/KDC/crypto/KDCcryptosign.d 


# Each subdirectory must supply rules for building sources it contributes
src/KDC/crypto/%.o: ../src/KDC/crypto/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


