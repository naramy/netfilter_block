all : netfilter_block

netfilter_block: nfqnl_test.cpp
	g++ -o $@ $^ -lnetfilter_queue

clean:
	rm -f netfilter_block
