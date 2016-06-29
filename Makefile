connbal: connbal.c hash.c packet.c
	$(CC) -o $@ $^

clean:
	rm -f connbal
