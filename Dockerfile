FROM alpine
MAINTAINER Jo Vanvoorden <jo.vanvoorden@telenet.be>
ADD ./bin/go-docker-iptables.lnx64 /bin/go-docker-iptables
CMD /bin/go-docker-iptables
