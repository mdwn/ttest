# ttest: Teleport cluster creation for testing

ttest will create and configure Teleport clusters for testing. It can use either a local
source copy of Teleport or use a Teleport binary for setting up the clusters with Teleport.
It is capable of adding child nodes to a Teleport server automatically.

## Config files

Config files are basically an amalgamation of Teleport configs along with a variety of
provider specific configs. Golang's `text/template` is used for interpolating individual
Teleport configs.

For a detailed example can be found in the examples directory.

## Clusters directory

`ttest` expects cluster config files to live in `src/ttest-clusters` by default. This
can be customized by setting the `TTEST_CLUSTERS_DIR` environment variable. The config
files are expected to be named `<cluster-name>.yaml`.

## Use

### `create` command

Once a config file  has been placed into the clusters directory, you can create it by running:

```
$ ttest create <cluster-name>
```

This will provision the infrastructure, build/distribute Teleport and then configure the cluster.

### `deploy` command

To update the Teleport binaries/configs on a cluster without attempting to re-provision the
infrastructure, you can run:

```
$ ttest deploy <cluster-name>
```

This will build/distribute Teleport and then configure the cluster.

### `destroy` command

This will remove all of the underlying infrastructure for the cluster. To do this, run:

```
$ ttest destroy <cluster-name>
```

### `nodes ls` command

You can list all nodes with their associated host names (if they're present) by running:

```
$ ttest nodes ls <cluster-name>
...
Node Name      Host
------------------------------
server         1.2.3.4
node1          1.2.3.5
node2          1.2.3.6
```

### `nodes ssh` command

In order to SSH into a node, you can run:

```
$ ttest nodes ssh <cluster-name> <node-name> [command]
```

Running without a supplied command will give you an interactive shell. Running with a command
will print the output and exit.

### `store dir` command

To see where the Terraform state is for a particular cluster, you can run:

```
$ ttest store dir
```

This will output the terraform store directory.

## Notes about created clusters.

The clusters created by this tool only have access enabled for the IP address that
you're currently on. If this changes you may have to adjust it manually or
re-provision.