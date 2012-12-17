################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CC_SRCS += \
../src/PASER/tables/PASER_neighbor_entry.cc \
../src/PASER/tables/PASER_neighbor_table.cc \
../src/PASER/tables/PASER_routing_entry.cc \
../src/PASER/tables/PASER_routing_table.cc \
../src/PASER/tables/PASER_rreq_list.cc 

OBJS += \
./src/PASER/tables/PASER_neighbor_entry.o \
./src/PASER/tables/PASER_neighbor_table.o \
./src/PASER/tables/PASER_routing_entry.o \
./src/PASER/tables/PASER_routing_table.o \
./src/PASER/tables/PASER_rreq_list.o 

CC_DEPS += \
./src/PASER/tables/PASER_neighbor_entry.d \
./src/PASER/tables/PASER_neighbor_table.d \
./src/PASER/tables/PASER_routing_entry.d \
./src/PASER/tables/PASER_routing_table.d \
./src/PASER/tables/PASER_rreq_list.d 


# Each subdirectory must supply rules for building sources it contributes
src/PASER/tables/%.o: ../src/PASER/tables/%.cc
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


