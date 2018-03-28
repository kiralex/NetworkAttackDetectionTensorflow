# Use an official Python runtime as a parent image
FROM nvidia/cuda:9.0-devel-ubuntu16.04


# Install python 3.5 and virtualenv
RUN apt-get update
RUN apt-get install -y python3-pip python3-dev python-virtualenv

# Folder to virtualenv
#RUN mkdir tensorflow
# Make virtualenv environment
#RUN virtualenv --system-site-packages -p python3 tensorflow
# Activate of the environment
#RUN ["/bin/bash", "-c", "source tensorflow/bin/activate"]

# Install of tensorflow with pip
RUN pip3 install --upgrade tensorflow-gpu

# Install scapy
RUN pip3 install scapy-python3

# Installation de snort
RUN apt-get install gcc flex bison make libpcap-dev libdnet-dev libdumbnet-dev libpcre3-dev libghc-zlib-dev wget -y

# mkdir && cd snort_src
WORKDIR snort_src

# Download and extract
# CMD wget
# ADD https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz .
# CMD ["tar", "-xvzf", "daq-2.0.6.tar.gz"]


RUN wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz \
    && tar -xvzf daq-2.0.6.tar.gz
RUN wget https://www.snort.org/downloads/snort/snort-2.9.11.1.tar.gz  \
    && tar -xvzf snort-2.9.11.1.tar.gz

# Build, configure
WORKDIR daq-2.0.6
CMD ["./configure"]
CMD ["make"]
CMD ["make install"]
WORKDIR ../snort-2.9.11.1
CMD ["./configure", "--enable-sourcefire"]
CMD ["make"]
CMD ["make install"]

# # snort without root right
RUN groupadd snort
RUN useradd snort -r -s /sbin/nologin -g snort


# Make folder/file tree
RUN mkdir -p /etc/snort/rules
RUN mkdir /var/log/snort
RUN mkdir /usr/local/lib/snort_dynamicrules
RUN chmod -R 5775 /etc/snort
# STEP 27
RUN chmod -R 5775 /var/log/snort
RUN chmod -R 5775 /usr/local/lib/snort_dynamicrules
RUN chown -R snort:snort /etc/snort
RUN chown -R snort:snort /var/log/snort
RUN chown -R snort:snort /usr/local/lib/snort_dynamicrules
RUN touch /etc/snort/rules/white_list.rules
RUN touch /etc/snort/rules/black_list.rules
# STEP 34
RUN touch /etc/snort/rules/local.rules

# Get config
RUN cp /snort_src/snort-2.9.11.1/etc/*.conf* /etc/snort
RUN cp /snort_src/snort-2.9.11.1/etc/*.map /etc/snort

# # Comment unnecessary import into snort.conf
RUN sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf

# Change rules folder path
RUN sed -i 's/var RULE\_PATH ..\/rules/var RULE\_PATH \/etc\/snort\/rules/' /etc/snort/snort.conf
RUN sed -i 's/var SO\_RULE\_PATH ..\/so\_rules/var SO\_RULE\_PATH \/etc\/snort\/so_rules /' /etc/snort/snort.conf


# RUN sed -i 's/var RULE\_PATH ..\/rules/var RULE\_PATH \/etc\/snort\/rules\//' /etc/snort/snort.conf

# RUN sed -i 's/var RULE\_PATH ..\/rules/var RULE\_PATH \/etc\/snort\/rules\//' /etc/snort/snort.conf
# RUN sed -i 's/var RULE\_PATH ..\/rules/var RULE\_PATH \/etc\/snort\/rules\//' /etc/snort/snort.conf





