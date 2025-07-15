<h2 align="center">Zygisk NoHello</h2>
<p align="center">
  A Zygisk module to hide root.
  </br>
  </br>
  <a href="https://github.com/MhmRdd/NoHello/actions/workflows/build.yml">
    <img src="https://github.com/MhmRdd/Il2Dump/actions/workflows/build.yml/badge.svg?branch=master" alt="Android CI status">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
  </br>
  <a href="https://github.com/MhmRdd/NoHello/issues">Report Bug</a>
    ·
  <a href="https://github.com/MhmRdd/NoHello/issues">Request Feature</a>
    ·
  <a href="https://github.com/MhmRdd/NoHello/releases">Latest Release</a>
</p>

> [!NOTE]
> This module currently focuses to hide root & zygisk from apps.
> Updates will gradually implements changes and fixes.

## About The Project

Using the **release** build is recommended over the debug build. Only use debug builds if you are going to make a bug report.

## Usage

### KernelSU & KernelSU Next users:
1. Install ZygiskNext or ReZygisk.
2. Make sure the unmount setting is enabled for the target app in the Manager.
3. Disable `Umount modules` in settings for Manager (if exists).
4. Disable `Enforce DenyList` in ZygiskNext/ReZygisk settings if there is one.

### APatch users:
1. Install ZygiskNext or ReZygisk.
2. Make sure the unmount setting is enabled for the target app in the Manager.
3. Disable `Enforce DenyList` in ZygiskNext/ReZygisk settings if there is one.

### Magisk users:
1. Update your Magisk to 28.0 or newer for better hiding capabilities. (optional)
2. Turn on Zygisk in Magisk settings (unrecommended) or install ZygiskNext/ReZygisk.
3. Turn off `Enforce DenyList` in Magisk settings.
4. Disable `Enforce DenyList` in ZygiskNext/ReZygisk settings if there is one. (if installed)
5. Add the target app to the deny list unless you're using a Magisk fork with a white list instead.

## Whitelisting (0.0.4+)
You can set the working mode to **whitelist** (instead of the default **blacklist**) by creating an empty regular file `/data/adb/nohello/whitelist`.
>[!WARNING]
> Using **Mount Rule System** with **whitelist**, can cause severe overheating & performance issues, due to how MRS being evaluated each time a process spawns.

This can be solved if you make NoHello evaluates Mount Rule System per boot/companion instance, by creating an empty regular file `/data/adb/nohello/umount_persist`/`data/adb/nohello/umount_persists`

## Mount Rule System

**Since version 0.0.5**, NoHello introduces **Mount Rule System**.</br>
This allows users to define **rules** that control how mount points are evaluated for **auto-unmounting**.</br>
Rules are fully configurable and match based on mount point properties like root path, mount path, filesystem type, or source.</br>
**MountRules** can be customized via `/data/adb/nohello/umount`.

### Rule Format

A rule is made up of **sections**, each consisting of a **keyword**, followed by a list of values enclosed in `{}`:

```
<keyword> { <value1> <value2> ... }
```

Valid **keywords** are:

| Keyword  | Matches against         | Supports Wildcards                                       | Description |
|----------|-------------------------|----------------------------------------------------------|-------------|
| `root`   | Root path of the mount  | Yes (`*`, escape by `\*`)                                | Root of the mount in `/proc/self/mountinfo` |
| `point`  | Mount point path        | Yes (`*`, escape by `\*` only at the beginning & ending) | Where the filesystem is mounted |
| `fs`     | Filesystem type         | No                                                       | Matches exact filesystem type, e.g. `ext4`, `erofs`, etc |
| `source` | Source device or file   | Yes (`*`, escape by `\*`)                                | e.g., `/dev/block/xyz`, `magisk`, etc |

### Example Rules

#### Match all `tmpfs` filesystems mounted under `/data/adb`:
```
fs { "tmpfs" } point { "/data/adb/*" }
```

#### Match anything mounted from a `tmpfs` source:
```
source { "tmpfs" }
```

#### Match a specific mount path exactly:
```
point { "/mnt/specific/path" }
```

#### Match any source ending with `data`:
```
source { "*data" }
```

#### Match root path starting with `/acct` and fs type `cgroup`:
```
root { "/acct*" } fs { "cgroup" }
```

### Quoting Values

You can quote values with **single or double quotes**:

```
point { "/mnt/with space" '/custom\ path' }
```

You may escape characters like `*`, `{`, `}`, and `"` using backslashes (`\`) if needed.

### Wildcard Behavior

Wildcards are supported only in `root`, `point`, and `source`. The supported patterns are:

- `*value*`: matches substring anywhere
- `*value`: matches suffix
- `value*`: matches prefix
- Exact match without `*`


>[!NOTE]
> - You can define **multiple rules**, each as a separate line.
> - All rules are evaluated independently.
> - Matching is case-sensitive and optimized for performance.


## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/FeatureName`)
3. Commit your Changes (`git commit -m 'Add some FeatureName'`)
4. Push to the Branch (`git push origin feature/FeatureName`)
5. Open a Pull Request.


## Acknowledgement

- [Zygisk Assistant](https://github.com/snake-4/Zygisk-Assistant)

## LICENSE

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

