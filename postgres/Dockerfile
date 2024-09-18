FROM postgres

RUN echo "deb http://security.debian.org/debian-security bullseye-security main contrib non-free" > /etc/apt/sources.list

RUN apt-get update

RUN rm /etc/apt/sources.list.d/pgdg.list && \
  apt-get update && apt-get -y install apt-transport-https && \
  echo "deb https://apt-archive.postgresql.org/pub/repos/apt/ stretch-pgdg main" > /etc/apt/sources.list.d/pgdg.list