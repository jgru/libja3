CC 		= gcc
BUILDDIR 	= ./build
SOURCEDIR 	= ./src
LIB 		= $(BUILDDIR)/libja3.a
OPT 		= -Wall -Werror -ggdb -O2
TARGET   	= $(BUILDDIR)/ja3sum
LDFLAGS  	= -lpcap -L$(BUILDDIR) -lja3  -lssl -lcrypto 
TESTDIR 	= ./tests
TEST_TARGET 	= $(BUILDDIR)/check_ja3_tests
TEST_LIBS 	= -lcheck -lsubunit -lm -lpthread -lrt 

all: $(TARGET) 

$(TARGET): $(LIB) 
	$(CC) $(OPT) $(SOURCEDIR)/ja3sum.c -o $@ $(LDFLAGS) 

_LIB_OBJS = ja3.o 
LIB_OBJS = $(patsubst %,$(BUILDDIR)/%,$(_LIB_OBJS))

_TEST_OBJS = check_ja3.o 
TEST_OBJS = $(patsubst %,$(BUILDDIR)/%,$(_TEST_OBJS))

$(LIB_OBJS): $(SOURCEDIR)/ja3.c
	$(CC) $(OPT) -c -o $@ $< -lssl -lcrypto

$(LIB): $(LIB_OBJS) 
	ar rcs $(LIB) $(LIB_OBJS) 

$(TEST_OBJS): $(TESTDIR)/check_ja3.c
	$(CC) $(OPT) -c -o $@ $< 

test: $(LIB) $(TEST_OBJS)
	$(CC) ./build/ja3.o $(TEST_OBJS)  -lssl -lcrypto  $(TEST_LIBS) -o $(TEST_TARGET)
clean:
	rm -f $(BUILDDIR)/*.o $(LIB) $(TARGET)  $(TEST_TARGET)

