@echo off

REM g++ -c ./src/*.cpp -I ./include
REM g++ -o ./bin/encrypt.exe *.o -L ./lib -lcstd

g++ -c ./src/*.cpp -I ../utils/include
g++ -o ./bin/encrypt.exe *.o -L ../utils/lib -lcstd

del *.o