#!/usr/bin/env python3
import argparse
import difflib
from pathlib import Path


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one anchor: {old!r}")
    return text.replace(old, new, 1)


def generate(common):
    source = common / "fs/ioctl.c"
    old = source.read_text()
    new = once(old, '#include "internal.h"\n',
               '#include "internal.h"\n#include "pvr_observe.h"\n')
    old_call = '''	error = do_vfs_ioctl(f.file, fd, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = vfs_ioctl(f.file, cmd, arg);
'''
    new_call = '''	{
		struct pvro_transaction *transaction;

		transaction = pvro_begin(f.file, cmd, arg);
		error = do_vfs_ioctl(f.file, fd, cmd, arg);
		if (error == -ENOIOCTLCMD)
			error = vfs_ioctl(f.file, cmd, arg);
		pvro_end(transaction, error);
	}
'''
    new = once(new, old_call, new_call)
    changes = [("fs/ioctl.c", old, new)]
    build = (common / "BUILD.bazel").read_text()
    modified_build = once(build,
        'load("//build/kernel/kleaf:constants.bzl", "X86_64_OUTS")',
        'load("//build/kernel/kleaf:constants.bzl", "DEFAULT_GKI_OUTS", "X86_64_OUTS")')
    modified_build = once(modified_build, '    "kernel_aarch64": {\n',
        '    "kernel_aarch64": {\n        "outs": DEFAULT_GKI_OUTS + [".config"],\n')
    changes.append(("BUILD.bazel", build, modified_build))
    makefile = (common / "fs/Makefile").read_text()
    if "pvr_observe.o" in makefile:
        raise ValueError("observer already integrated")
    changes.append(("fs/Makefile", makefile,
                    makefile + "\nobj-$(CONFIG_DEBUG_FS) += pvr_observe.o\n"))
    for name in ("pvr_observe.c", "pvr_observe.h"):
        if (common / "fs" / name).exists():
            raise ValueError(f"destination already exists: {name}")
        changes.append((f"fs/{name}", "", Path(__file__).with_name(name).read_text()))
    result = []
    for name, before, after in changes:
        result.extend(difflib.unified_diff(
            before.splitlines(keepends=True), after.splitlines(keepends=True),
            fromfile=f"a/{name}" if before else "/dev/null", tofile=f"b/{name}"))
    return "".join(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("common", type=Path)
    args = parser.parse_args()
    print(generate(args.common), end="")
