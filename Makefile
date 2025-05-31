CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iincludes
LDFLAGS = -lmysqlcppconn -lpthread

SRC = main.cpp \
      includes/bcrypt.cpp \
      includes/blowfish.cpp

OBJ = $(SRC:.cpp=.o)
TARGET = server_app

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
