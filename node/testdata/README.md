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

The launcher creates an editable `node.yaml` on first use, including the `files`
mount. Subsequent starts preserve the file. Edit ports, limits and grants there;
Make port overrides only affect initial creation. Changes apply on restart.
Each node keeps its local configuration in `node/testdata/node*/node.yaml`,
encrypted state in `node/testdata/node*/state/`, and identity keys in
`node/testdata/node*/keys/`. All three paths are ignored by Git. Existing legacy
`data` directories are not migrated. The development key is public fixture
material and must never be used for a deployment.
