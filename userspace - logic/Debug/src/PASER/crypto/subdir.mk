################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/crypto/PASER_crypto_hash.cc \
../src/PASER/crypto/PASER_crypto_sign.cc \
../src/PASER/crypto/PASER_root.cc 

OBJS += \
./src/PASER/crypto/PASER_crypto_hash.o \
./src/PASER/crypto/PASER_crypto_sign.o \
./src/PASER/crypto/PASER_root.o 

CC_DEPS += \
./src/PASER/crypto/PASER_crypto_hash.d \
./src/PASER/crypto/PASER_crypto_sign.d \
./src/PASER/crypto/PASER_root.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/crypto/%.o: ../src/PASER/crypto/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


