FROM debian:bullseye
COPY arpproxy /usr/sbin
#this won't work in docker since we'll need arp access
#EXPOSE 179/tcp
ENTRYPOINT ["/usr/sbin/arpproxy"]
