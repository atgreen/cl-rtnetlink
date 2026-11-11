;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-rtnetlink/tests)
(in-suite cl-rtnetlink)

(test encodes-native-netlink-primitives
  (is (= 4 (netlink-align 1)))
  (is (= 8 (netlink-align 8)))
  (let ((bytes (netlink-integer #x12345678 4)))
    (is (= #x12345678 (netlink-read-integer bytes 0 4))))
  (is (equalp #(97 98 99 0) (netlink-string "abc")))
  (is (= 8 (length (netlink-attribute 3 #(1 2 3))))))

(test parses-acknowledgements-and-kernel-errors
  (let ((ack (netlink-message 2 0 (netlink-integer 0 4))))
    (multiple-value-bind (messages acknowledged)
        (parse-netlink-reply ack (length ack) 1)
      (is (null messages))
      (is-true acknowledged)))
  (let ((failure (netlink-message 2 0 (netlink-integer -1 4))))
    (handler-case
        (progn (parse-netlink-reply failure (length failure) 1)
               (fail "kernel EPERM must fail"))
      (rtnetlink-error (condition)
        (is (= 1 (rtnetlink-error-errno condition)))))))

(test rejects-truncated-and-malformed-replies
  (signals rtnetlink-protocol-error (parse-netlink-reply #(0 0 0) 3 1))
  (let ((message (netlink-message 2 0 #())))
    (signals rtnetlink-protocol-error
      (parse-netlink-reply message (length message) 1)))
  (let ((message (netlink-message 16 0 #(1 2 3 4))))
    (signals rtnetlink-protocol-error
      (parse-netlink-reply message (1- (length message)) 1))))

(test correlates-sequences-and-keeps-data-before-ack
  (let* ((unrelated (netlink-message 2 0 (netlink-integer -1 4) 2))
         (data (netlink-message 16 0 #(1 2 3 4)))
         (ack (netlink-message 2 0 (netlink-integer 0 4)))
         (batch (netlink-octets unrelated data ack)))
    (multiple-value-bind (messages acknowledged)
        (parse-netlink-reply batch (length batch) 1)
      (is-true acknowledged)
      (is (= 1 (length messages)))
      (is (equalp data (first messages))))))

(test reads-a-live-kernel-link-without-privileges
  (let* ((index (interface-index "lo"))
         (messages (call-rtnetlink 18 0 (netlink-interface-message :index index))))
    (is (plusp index))
    (is (= 1 (length messages)))
    (is (= 16 (netlink-read-integer (first messages) 4 2)))
    (is (= index (netlink-read-integer (first messages) 20 4)))))

(test validates-names-addresses-and-prefix-decoding
  (dolist (name '("" "." ".." "veth/unsafe" "a b" "1234567890123456"))
    (signals rtnetlink-protocol-error (validate-network-interface-name name)))
  (is (string= "veth-safe_1" (validate-network-interface-name "veth-safe_1")))
  (is (equalp #(192 0 2 17) (ipv4-network-octets "192.0.2.17")))
  (multiple-value-bind (family bytes bits) (network-address-wire-values "2001:db8::17")
    (is (= 10 family))
    (is (= 16 (length bytes)))
    (is (= 128 bits)))
  (is (= #x0a500000 (network-prefix-octets-integer #(10 80) 32))))

(test parses-live-link-attributes
  (let ((attributes (network-link-attributes "lo")))
    (is (hash-table-p attributes))
    (is (plusp (hash-table-count attributes)))))
