FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
#COPY ./sources.list /etc/apt/sources.list
#COPY ./gdbinit /home/root/.gdbinit
RUN ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    apt-get update && \
    apt-get install -y build-essential git cmake software-properties-common locales locales-all \
    openssl libssl-dev pkg-config clang automake libtool xsltproc docbook-xsl \
    openssh-server netcat iptables curl iproute2 conntrack dnsutils tcpdump  iputils-ping net-tools vim valgrind

#RUN mkdir /var/run/sshd  && echo 'root:root' | chpasswd  && \
#    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config &&  \
#    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
# RUN echo "/var/log/core-%e-%p-%s-%t" > /proc/sys/kernel/core_pattern

RUN mkdir /home/dev && mkdir /tmp/log
WORKDIR /home/dev
EXPOSE 22

#CMD ["/usr/sbin/sshd", "-D"]
#
# RUN mkdir /src/picoquic
# COPY ./ /src/picoquic/
#
# # Perl stuff is for the picotls test code
# RUN echo install Test::TCP | perl -MCPAN -
# RUN echo install Scope::Guard | perl -MCPAN -
#
# RUN git clone https://github.com/h2o/picotls.git && \
#     cd picotls && \
#     git submodule init && \
#     git submodule update && \
#     cmake . && \
#     make && \
#     make check
#
# RUN cd /src/picoquic && \
#     cmake . && \
#     make
