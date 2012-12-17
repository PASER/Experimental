################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/PASER/gps/NMEAData.cpp \
../src/PASER/gps/NMEAParser.cpp \
../src/PASER/gps/gpsReader.cpp 

OBJS += \
./src/PASER/gps/NMEAData.o \
./src/PASER/gps/NMEAParser.o \
./src/PASER/gps/gpsReader.o 

CPP_DEPS += \
./src/PASER/gps/NMEAData.d \
./src/PASER/gps/NMEAParser.d \
./src/PASER/gps/gpsReader.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/gps/%.o: ../src/PASER/gps/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


