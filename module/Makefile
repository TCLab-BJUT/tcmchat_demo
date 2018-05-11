dirs= login_verify sm4_attack msg_broadcast
all:
	$(foreach N,$(dirs),make -C $(N) || exit "$$?";)
clean:
	rm -f ../plugin/*.so ../plugin/*.cfg
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~


