# Mountall enhancements for ZFS on Linux

The home for this git repository is:

* https://github.com/zfsonlinux/mountall

Mountall packages in the ZoL PPA at https://launchpad.net/~zfs-native are built
from this repository using the git-buildpackage tool.


## Casual Build Instructions

Just do quick builds like this:
```
$ apt-get source --build mountall
$ apt-get source --build mountall
```

## Developer Build Instructions

1. Clone this repository:
```
$ git clone git://github.com/zfsonlinux/mountall.git
$ cd mountall
```

1. List the current releases by branch name:
```
$ git branch --list 'master/*'
```

1. Or list previous releases by tag name:
```
$ git tag --list 'master/*
```

1. Checkout the branch name or tag name that you want to build.  For example,
the latest code for Ubuntu 12.04 Precise Pangolin is:
```
$ git checkout master/ubuntu/precise
```

1. Now compile it:
```
$ git-buildpackage -uc -us
```

1. And clean the working tree afterwards by doing this:
```
$ git clean -df
$ git reset --hard
```


## Upstream Repositories

Each of the `upstream` branches in this repository is an unmodified copy of an
official distribution repository, like those hosted by the Debian or Ubuntu
projects.  The `git-buildpackage` framework combines an `upstream` branch with
the corresponding `patch-queue` branch to create a `master` branch.

By default, git will pull the `upstream` branches from the clone origin at
Github and not the actual upstream respositories.  Look at the `git-config.txt`
file in the `readme` branch for an example of how to configure remotes that
pull from the official distribution repositories.

Some of the remotes for this repository are bzr repositories at Launchpad.
Pulling through bzr requires this bridge helper:

https://github.com/felipec/git/blob/fc/remote/bzr/contrib/remote-helpers/git-remote-bzr

Just download that file directly into the `/usr/local/bin` directory and make
it executable.  Also run `bzr launchpad-login` to ensure that you have a
working bazaar installation.

The `upstream` branches for Ubuntu may be disconnected or incomplete because
Ubuntu does not always use source control for system updates.
