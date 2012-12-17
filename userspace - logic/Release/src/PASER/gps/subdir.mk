################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/PASER/gps/PASER_NMEAData.cpp \
../src/PASER/gps/PASER_NMEAParser.cpp \
../src/PASER/gps/PASER_gpsReader.cpp 

OBJS += \
./src/PASER/gps/PASER_NMEAData.o \
./src/PASER/gps/PASER_NMEAParser.o \
./src/PASER/gps/PASER_gpsReader.o 

CPP_DEPS += \
./src/PASER/gps/PASER_NMEAData.d \
./src/PASER/gps/PASER_NMEAParser.d \
./src/PASER/gps/PASER_gpsReader.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/gps/%.o: ../src/PASER/gps/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


