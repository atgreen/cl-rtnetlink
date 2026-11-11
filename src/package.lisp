;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(defpackage #:cl-rtnetlink
  (:use #:cl)
  (:export
   #:rtnetlink-error #:rtnetlink-error-errno #:rtnetlink-protocol-error
   #:netlink-octets #:netlink-integer #:netlink-read-integer #:netlink-align
   #:netlink-string #:netlink-attribute #:netlink-message
   #:parse-netlink-reply #:call-rtnetlink #:netlink-interface-message
   #:interface-index #:validate-network-interface-name
   #:netlink-attributes #:network-link-attributes-by-index #:network-link-attributes
   #:network-octets-integer #:network-prefix-octets-integer
   #:set-network-link-mtu #:set-network-link-up #:delete-network-link
   #:ipv4-network-octets #:network-address-wire-values
   #:add-network-address #:remove-network-address #:network-address-present-p
   #:replace-network-route #:remove-network-route #:network-route-present-p
   #:replace-permanent-network-neighbor #:permanent-network-neighbor-p))
