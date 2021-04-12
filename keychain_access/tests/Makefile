TARGET = hackme

all: $(TARGET)-objc $(TARGET)-swift

$(TARGET)-objc: $(TARGET).m
	gcc -framework Foundation -framework Security -o $@ $<

$(TARGET)-swift: $(TARGET).swift
	swiftc -o $@ $<

.PHONY: all
