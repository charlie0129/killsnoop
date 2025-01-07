# killsnoop

A killsnoop is a tool that monitors the system for kill signals and logs the process that received the signal. It is useful for finding out which process is being killed and by whom. It is like [bcc/killsnoop](https://github.com/iovisor/bcc/blob/master/tools/killsnoop.py) but with more detailed information.

## Features

- Display the signal source (who sent the signal) and target (who received the signal) in realtime
- Process cmdline included. [^1]
- Process tree included. [^1]

[^1]: While basic information (source pid, ppid, comm, cmdline and targe pid) and collected in kernel space (which is more reliable), detailed process information (target cmdline, process tree, and etc.) is collected in user space periodically, which will miss ephemeral processes. So these information can sometimes be omitted in the log.

## Sample output

Log output is in `logfmt` so you can easily parse it with log parsers. Here is some sample output (newlines added for readability):

```
level=INFO
msg="snooped signal"
signal=15                 # <-- What signal?
signalString=terminated
source.pid=1646437        # <-- Who sent this signal?
source.cmdline=[runc]     # <-- Who sent this signal?
source.comm=runc          # <-- Who sent this signal?
source.parent.pid=1645247
target.pid=1645331        # <-- Who received this signal?
target.cmdline="[python /main.py --port=8080]" # <-- Who received this signal? (this field may not exist)
target.comm=python        # <-- Who received this signal? (this field may not exist)
target.parent.pid=1645238
target.parent.cmdline="[/usr/bin/containerd-shim-runc-v2 -namespace k8s.io -id 4813c0ed0a96d843b694a980527bb9b628ccbe9052237ce4260274e4a95ac25d -address /run/containerd/containerd.sock]"
target.parent.comm=containerd-shim
... (deeper process tree omitted)
```

If we run `yes` and then killed it by `pkill yes`,

```
yes >/dev/null &
sleep 5
pkill yes
```

the output will be:

```
level=INFO
msg="snooped signal"
signal=15                 # <-- What signal?
signalString=terminated
source.pid=1657512        # <-- Who sent this signal?
source.cmdline=[pkill]    # <-- Who sent this signal?
source.comm=pkill         # <-- Who sent this signal?
source.parent.pid=1657386
source.parent.cmdline=[-zsh]
source.parent.comm=zsh
... (deeper process tree omitted)
target.pid=1657487        # <-- Who received this signal?
target.cmdline=[yes]      # <-- Who received this signal? (this field may not exist)
target.comm=yes           # <-- Who received this signal? (this field may not exist)
target.parent.pid=1657386
target.parent.cmdline=[-zsh]
target.parent.comm=zsh
... (deeper process tree omitted)
```

## Building

> [!NOTE]
> Ideally, the build machine should be on the same kernel (same version, same kconfig) as the target machine because this program relies on certain kernel structs (task_struct, mm_struct, and etc.), which are prone to change in different kernels. However, if it is working as expected, you can ignore this.

Aside from `golang`, install these dependencies (to build BTF):

```
# On Debian/Ubuntu:
apt-get install gcc-multilib clang llvm libelf-dev libbpf-dev
# On Alpine:
apk add clang-dev llvm-dev libbpf-dev linux-headers musl-dev
```

Build:

```
make clean
make
```

> [!NOTE]
> The default build option ignores SIG 0. To include SIG 0, run `CFLAGS= make`

## Running in containers

Necessary volumes and permissions must be given:

```
docker run --rm -it \
    -v /proc:/host/proc:ro \
    -v /sys/fs/bpf:/sys/fs/bpf:rw \
    -v /sys/kernel/tracing:/sys/kernel/tracing:rw \
    --cap-add BPF \
    --cap-add PERFMON \
    --cap-add SYS_ADMIN \
    charlie0129/killsnoop:v0.2.0-debian-12-kernel-6.1 --root /host
```

- `/proc`: finding process tree and detailed info
- `/sys/fs/bpf`: bpf maps
- `/sys/kernel/tracing`: tracep sys_kill
- `CAP_BPF`: employ privileged BPF operations
- `CAP_PERFMON`: load tracing programs
- `CAP_SYS_ADMIN`: iterate system wide loaded programs, maps, links, BTFs
