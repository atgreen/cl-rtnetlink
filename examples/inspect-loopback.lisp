;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(require :asdf)
(asdf:load-system :cl-rtnetlink)

(let* ((index (cl-rtnetlink:interface-index "lo"))
       (attributes (cl-rtnetlink:network-link-attributes-by-index index)))
  (format t "loopback index: ~D~%attributes: ~D~%"
          index (hash-table-count attributes)))
