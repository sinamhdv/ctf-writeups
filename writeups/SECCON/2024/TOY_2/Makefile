all:
	g++ -std=c++20 -g -o dbg toy2.cpp
	patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./dbg
