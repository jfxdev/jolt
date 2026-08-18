# Local node test data

The three development nodes keep independent state:

| Node | API | mTLS | Token | Filesystem test path |
| --- | --- | --- | --- | --- |
| `nodeA` | `127.0.0.1:18081` | `127.0.0.1:18441` | `development-node-a-token` | `node/testdata/nodeA/files` |
| `nodeB` | `127.0.0.1:18082` | `127.0.0.1:18442` | `development-node-b-token` | `node/testdata/nodeB/files` |
| `nodeC` | `127.0.0.1:18083` | `127.0.0.1:18443` | `development-node-c-token` | `node/testdata/nodeC/files` |

Run all nodes from the repository root:

```sh
make nodes
```

Or run one node with `make node-a`, `make node-b`, or `make node-c`.
Ports and tokens can be overridden:

```sh
make nodes NODE_A_API_PORT=19081 NODE_A_TOKEN=another-token
```

When creating mounts through the Control Tower, use the absolute path shown by:

```sh
pwd
```

followed by `/node/testdata/nodeA/files`, `/node/testdata/nodeB/files`, or
`/node/testdata/nodeC/files`. Each node's SQLite database and identity keys
stay in its own `data` and `keys` directories.
