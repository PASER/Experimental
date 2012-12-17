################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/PASER/timer_management/subdir.mk
-include src/PASER/tables/subdir.mk
-include src/PASER/syslog/subdir.mk
-include src/PASER/statistics/subdir.mk
-include src/PASER/scheduler/subdir.mk
-include src/PASER/route_maintenance/subdir.mk
-include src/PASER/route_discovery/subdir.mk
-include src/PASER/plugin/subdir.mk
-include src/PASER/paser_socket/subdir.mk
-include src/PASER/packet_structure/subdir.mk
-include src/PASER/packet_processing/subdir.mk
-include src/PASER/gps/subdir.mk
-include src/PASER/crypto/subdir.mk
-include src/PASER/config/subdir.mk
-include src/PASER/cfgparser/subdir.mk
-include src/KDC/scheduler/subdir.mk
-include src/KDC/crypto/subdir.mk
-include src/KDC/config/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: PASER

# Tool invocations
PASER: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross G++ Linker'
	g++  -o "PASER" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(C++_DEPS)$(OBJS)$(C_DEPS)$(CC_DEPS)$(CPP_DEPS)$(EXECUTABLES)$(CXX_DEPS)$(C_UPPER_DEPS) PASER
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
