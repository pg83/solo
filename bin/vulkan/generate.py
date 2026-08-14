#!/usr/bin/env python3

import re
import sys
from pathlib import Path


def writeAlltypes(output, inputs):
    rules = (
        (
            re.compile(r"^TYPEDEF (.*) ([^ ]*);$"),
            "#if defined(__NEED_{1}) && !defined(__DEFINED_{1})\n"
            "typedef {0} {1};\n"
            "#define __DEFINED_{1}\n"
            "#endif",
        ),
        (
            re.compile(r"^STRUCT *([^ ]*) (.*);$"),
            "#if defined(__NEED_struct_{0}) && !defined(__DEFINED_struct_{0})\n"
            "struct {0} {1};\n"
            "#define __DEFINED_struct_{0}\n"
            "#endif",
        ),
        (
            re.compile(r"^UNION *([^ ]*) (.*);$"),
            "#if defined(__NEED_union_{0}) && !defined(__DEFINED_union_{0})\n"
            "union {0} {1};\n"
            "#define __DEFINED_union_{0}\n"
            "#endif",
        ),
    )
    lines = []
    for path in inputs:
        for line in path.read_text().splitlines():
            for pattern, replacement in rules:
                match = pattern.match(line)
                if match:
                    line = replacement.format(*match.groups())
                    break
            lines.append(line)
    output.write_text("\n".join(lines) + "\n")


def writeSyscall(output, source):
    text = source.read_text()
    aliases = []
    for line in text.splitlines():
        if "__NR_" in line:
            aliases.append(line.replace("__NR_", "SYS_", 1))
    output.write_text(text.rstrip() + "\n" + "\n".join(aliases) + "\n")


def writeVersion(output, source):
    output.write_text(f'#define VERSION "{source.read_text().strip()}"\n')


def writeLibcxxConfig(output, source):
    definitions = {
        "_LIBCPP_ABI_VERSION": "1",
        "_LIBCPP_ABI_NAMESPACE": "__1",
        "_LIBCPP_HAS_MUSL_LIBC": None,
        "_LIBCPP_HAS_THREAD_API_PTHREAD": None,
        "_LIBCPP_HAS_NO_VENDOR_AVAILABILITY_ANNOTATIONS": None,
        "_LIBCPP_HAS_NO_TIME_ZONE_DATABASE": None,
        "_LIBCPP_PSTL_CPU_BACKEND_THREAD": None,
        "_LIBCPP_HARDENING_MODE_DEFAULT": "2",
    }
    lines = []
    for line in source.read_text().splitlines():
        match = re.match(r"^#cmakedefine ([A-Z0-9_]+)(?: (.*))?$", line)
        if match:
            name, value = match.groups()
            if name in definitions:
                replacement = definitions[name]
                if value:
                    value = value.replace(f"@{name}@", replacement)
                    lines.append(f"#define {name} {value}")
                else:
                    lines.append(f"#define {name}")
            else:
                lines.append(f"/* #undef {name} */")
        elif line in ("@_LIBCPP_ABI_DEFINES@", "@_LIBCPP_EXTRA_SITE_DEFINES@"):
            lines.append("")
        else:
            lines.append(line)
    output.write_text("\n".join(lines) + "\n")


def main():
    action = sys.argv[1]
    output = Path(sys.argv[2])
    inputs = [Path(path) for path in sys.argv[3:]]
    output.parent.mkdir(parents=True, exist_ok=True)
    if action == "alltypes":
        writeAlltypes(output, inputs)
    elif action == "syscall":
        writeSyscall(output, inputs[0])
    elif action == "version":
        writeVersion(output, inputs[0])
    elif action == "libcxx-config":
        writeLibcxxConfig(output, inputs[0])
    else:
        raise ValueError(f"unknown action: {action}")


if __name__ == "__main__":
    main()
