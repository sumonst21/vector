---
last_modified_on: "2020-07-13"
title: Install Vector via Nix
sidebar_label: Nix
description: Install Vector through the Nix package manager
---

import Alert from '@site/src/components/Alert';
import CodeExplanation from '@site/src/components/CodeExplanation';
import ConfigExample from '@site/src/components/ConfigExample';
import DaemonDiagram from '@site/src/components/DaemonDiagram';
import Jump from '@site/src/components/Jump';
import Steps from '@site/src/components/Steps';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

Vector can be installed through the [Nix package manager][urls.nix] via
[Vector's Nix package][urls.vector_nix_package]. This package manager is
generally used on [NixOS][urls.nixos].

<Alert type="warning">

Because Vector must be manually updated on Nix, new Vector releases will be
delayed. Generally new Vector releases are made available within a few days.

</Alert>

<!--
     THIS FILE IS AUTOGENERATED!

     To make changes please edit the template located at:

     website/docs/setup/installation/package-managers/nix.md.erb
-->

## Install

<Tabs
  block={true}
  defaultValue="daemon"
  values={[{"label":"As a Daemon","value":"daemon"}]}>
<TabItem value="daemon">

The [daemon deployment strategy][docs.strategies#daemon] is designed for data
collection on a single host. Vector runs in the background, in its own process,
collecting _all_ data for that host.
Typically data is collected from a process manager, such as Journald via
Vector's [`journald` source][docs.sources.journald], but can be collected
through any of Vector's [sources][docs.sources].
The following diagram demonstrates how it works.

<DaemonDiagram
  platformName={null}
  sourceName={null}
  sinkName={null} />

---

<Tabs
  centered={true}
  className={"rounded"}
  defaultValue={"nix"}
  placeholder="Please choose an installation method..."
  select={false}
  size={null}
  values={[{"group":"Package managers","label":"Nix","value":"nix"}]}>
<TabItem value="nix">

<Steps headingDepth={3}>

1.  ### Install Vector

    ```bash
    nix-env --file https://github.com/NixOS/nixpkgs/archive/master.tar.gz --install --attr vector
    ```

    <CodeExplanation>

    * The `--file` flag ensures that you're installing the latest stable version
      of Vector (0.10.0).
    * The `--attr` improves installation speed.

    </CodeExplanation>

    [Looking for a specific version?][docs.package_managers.nix#versions]

2.  ### Configure Vector

    <ConfigExample
      format="toml"
      path={"/etc/vector/vector.toml"}
      sourceName={"journald"}
      sinkName={null} />

3.  ### Start Vector

    ```bash
    vector --config /etc/vector/vector.toml
    ```

    <CodeExplanation>

    * `vector` is placed in your `$PATH`.
    * You must create a [Vector configuration file][docs.configuration] to
      successfully start Vector.

    </CodeExplanation>

</Steps>

</TabItem>
</Tabs>
</TabItem>
</Tabs>

## Configuring

The [Vector nix package][urls.vector_nix_package] does not install any
configuration files by default. You'll need to create a
[Vector configuration file][docs.configuration] and pass it to Vector via the
`--config` flag when [starting][docs.process-management#starting] Vector.

## Deploying

How you deploy Vector is largely dependent on your use case and environment.
Please see the [deployment section][docs.deployment] for more info on how to
deploy Vector.

## Administering

The Vector nix package does not use Systemd by default, but Vector does provide
a [Systemd service file][urls.vector_systemd_file] that you can use as a
starting point. How you manage the Vector process is up to you, and the
process administration section covers how to do this:

<Jump to="/docs/administration/">Administration</Jump>

## Uninstalling

```bash
nix-env --uninstall vector
```

## Updating

```bash
nix-env --file https://github.com/NixOS/nixpkgs/archive/master.tar.gz --upgrade vector
```

## Package

### Architectures

Vector's Nix packages only support the X86_64 architecture.

### Versions

Installing previous versions of Vector through `nix` is possible, but not
straightforward. For example, installing Vector `0.7.1` can be achieved with
the following command:

```bash
nix-env --file https://github.com/NixOS/nixpkgs/archive/20bbe6cba68fb9d37b5d0e373b6180dce2961e0d.tar.gz --install --attr vector
```

`20bbe6...` represents the commit sha for the `0.7.1` on the
[nix package repo][urls.vector_nix_package].

#### Listing Versions & Commit SHAs

For situations that required automated retrieval, we've thrown thogether this
handy Ruby function that will list the Vector versions and their commit sha:

```ruby
require "net/http"
require "json"

# Returns a hash mapping Vector versions to commits in `nixpkgs/nixos` repository
def nix_versions
  nixpkgs_repo = "nixos/nixpkgs"
  commits_url = "https://api.github.com/repos/#{nixpkgs_repo}/commits?path=pkgs/tools/misc/vector"

  response = Net::HTTP.get URI(commits_url)
  items = JSON.parse response

  versions = {}
  for item in items do
    match = item["commit"]["message"].match "^vector:.*(\\d+\.\\d+\.\\d+)$"
    if match
      version = match[1]
      versions[version] = item["sha"]
    end
  end

  versions
end
```

### Source Files

Vector's Nix source files are located in the
[Nix repo][urls.vector_nix_package].

[docs.configuration]: /docs/setup/configuration/
[docs.deployment]: /docs/setup/deployment/
[docs.package_managers.nix#versions]: /docs/setup/installation/package-managers/nix/#versions
[docs.process-management#starting]: /docs/administration/process-management/#starting
[docs.sources.journald]: /docs/reference/sources/journald/
[docs.sources]: /docs/reference/sources/
[docs.strategies#daemon]: /docs/setup/deployment/strategies/#daemon
[urls.nix]: https://nixos.org/nix/
[urls.nixos]: https://nixos.org/
[urls.vector_nix_package]: https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/misc/vector/default.nix
[urls.vector_systemd_file]: https://github.com/timberio/vector/blob/master/distribution/systemd/vector.service
