# Makefile for AppArmor Linux Security Module
#
subdir-$(CONFIG_SECURITY_APPARMOR) += match
obj-$(CONFIG_SECURITY_APPARMOR) += apparmor.o

apparmor-y := main.o list.o procattr.o lsm.o apparmorfs.o capabilities.o module_interface.o
