FROM debian:bullseye@sha256:3066ef83131c678999ce82e8473e8d017345a30f5573ad3e44f62e5c9c46442b

RUN apt update -qq && apt upgrade --no-install-recommends -yqq \
  && apt install --no-install-recommends -yqq procps python3-pip uwsgi uwsgi-plugin-python3 python3-setuptools nginx runit \ 
  && mkdir /etc/service/nginx \
  && mkdir /etc/service/wsgi

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx.runit /etc/service/nginx/run
COPY wsgi.runit /etc/service/wsgi/run

WORKDIR /pinserver
COPY runit_boot.sh wsgi.ini requirements.txt wsgi.py server.py lib.py pindb.py __init__.py generateserverkey.py flaskserver.py /pinserver/
RUN pip3 install --upgrade pip wheel
RUN pip3 install --require-hashes -r /pinserver/requirements.txt
CMD ["/bin/bash", "-c", "chown www-data:www-data /pins; ./runit_boot.sh"]
