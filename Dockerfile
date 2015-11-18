#
#  vim:ts=2:sw=2:et
#
FROM alpine:latest
MAINTAINER Rohith <gambol99@gmail.com>

ADD bin/openvpn-authd /opt/bin/openvpn-authd
ADD public/ /opt/bin/public
ADD templates/ /opt/bin/templates
RUN chmod +x /opt/bin/openvpn-authd

WORKDIR "/opt/bin"

ENTRYPOINT [ "/opt/bin/openvpn-authd" ]
