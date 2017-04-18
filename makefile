CC = gcc
CFLAGS = -Wall
LDFLAGS =
OBJFILES =parser.o stackadt.o stack_ptr.o rule_table.o parseTable.o driver.o lexer.o symbolTable.o ast.o 
TARGET = stage1exe
all: $(TARGET)
$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
clean:
	rm -f $(OBJFILES) $(TARGET)