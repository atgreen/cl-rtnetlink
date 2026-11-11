# cl-rtnetlink

`cl-rtnetlink` is an SBCL client for Linux `NETLINK_ROUTE`. It encodes the
kernel UAPI directly and opens a private netlink socket for every transaction,
so operations run in the calling thread's current network namespace.

It provides message and attribute codecs, correlated ACK/error handling, link
inspection and updates, IPv4/IPv6 address operations, routes, and permanent
neighbors. It does not invoke command-line networking tools or retain policy.

## Usage

```lisp
(asdf:load-system :cl-rtnetlink)

(let ((index (cl-rtnetlink:interface-index "lo")))
  (format t "loopback index: ~D~%" index)
  (format t "attributes: ~D~%"
          (hash-table-count
           (cl-rtnetlink:network-link-attributes-by-index index))))
```

Mutation operations generally require `CAP_NET_ADMIN`; inspection of an
existing link does not. Kernel errors are reported as `rtnetlink-error` with
the original errno. Malformed protocol data signals
`rtnetlink-protocol-error`.

## Testing

```sh
sbcl --noinform --non-interactive \
     --eval '(require :asdf)' \
     --eval '(asdf:test-system :cl-rtnetlink)'
```

The suite includes a live, read-only `RTM_GETLINK` transaction against the
loopback interface.

## Author

Anthony Green <green@moxielogic.com>

## License

MIT. See `LICENSE`.
