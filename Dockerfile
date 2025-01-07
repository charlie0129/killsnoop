FROM scratch
COPY killsnoop /
ENTRYPOINT ["/killsnoop"]
