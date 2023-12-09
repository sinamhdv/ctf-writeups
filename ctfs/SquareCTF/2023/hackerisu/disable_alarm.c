// compile this as an SO file and use with LD_PRELOAD to disable game timeout for debugging
// $ gcc -shared -o preload.so disable_alarm.c
// $ LD_PRELOAD=./preload.so ./game-distr.out
void alarm(int x) {}
