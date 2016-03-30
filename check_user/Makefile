CC=arm-none-linux-gnueabi-gcc

LDFLAGS= -L ./lib -lm -lcrypto -lrt -lcurl -lSecuTFMcApi


SRC=*.c
INC= -I./include

TARGET = sslvpn


all:$(TARGET)
sslvpn:$(SRC)
	$(CC) -o $(TARGET) $(SRC) $(INC) $(LDFLAGS) $(CFLAGS)

clean:
	@rm *.o $(TARGET) bin/$(TARGET) -f

