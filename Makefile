SnortingPackets: main.cpp
	g++ main.cpp -o SnortingPackets -ltins
clean:
	rm -f *.o SnortingPackets