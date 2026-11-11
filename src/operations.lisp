;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-rtnetlink)

(defun parse-ipv4-integer (address)
  "Parse dotted-quad ADDRESS into an unsigned integer."
  (let ((parts (uiop:split-string address :separator '(#\.))))
    (unless (and (= 4 (length parts))
                 (every (lambda (part)
                          (and (plusp (length part))
                               (every #'digit-char-p part)
                               (or (= 1 (length part))
                                   (char/= #\0 (char part 0)))
                               (<= (parse-integer part) 255)))
                        parts))
      (fail-protocol "invalid IPv4 address ~S" address))
    (reduce (lambda (value part) (+ (ash value 8) (parse-integer part)))
            parts :initial-value 0)))

(defun validate-network-interface-name (name)
  "Return NAME when it is a safe Linux interface name -- a string of 1 to 15
   characters drawn from [A-Za-z0-9-_.] that is neither \".\" nor \"..\" -- and
   signal RTNETLINK-PROTOCOL-ERROR otherwise. Guards names before they reach the kernel or a
   namespace path."
  (unless (and (stringp name) (<= 1 (length name) 15)
               (every (lambda (character)
                        (or (and (char<= #\a character #\z))
                            (and (char<= #\A character #\Z))
                            (and (char<= #\0 character #\9))
                            (find character "-_."))) name)
               (not (member name '("." "..") :test #'string=)))
    (fail-protocol "unsafe network interface name ~S" name))
  name)


(defun netlink-attributes (message offset)
  "Parse the netlink attributes in MESSAGE from OFFSET into a hash table from
   attribute type (with the nested/byte-order flag bits masked off) to its raw
   payload bytes. Signals RTNETLINK-PROTOCOL-ERROR on a truncated or malformed attribute."
  (let ((attributes (make-hash-table)))
    (loop while (< offset (length message))
          do (when (< (- (length message) offset) 4)
               (fail-protocol "truncated rtnetlink attribute"))
             (let ((size (netlink-read-integer message offset 2))
                   (type (logand #x3fff
                                 (netlink-read-integer message (+ offset 2) 2))))
               (unless (<= 4 size (- (length message) offset))
                 (fail-protocol "invalid rtnetlink attribute length"))
               (setf (gethash type attributes)
                     (subseq message (+ offset 4) (+ offset size)))
               (incf offset (netlink-align size))))
    attributes))

(defun network-link-attributes-by-index (index)
  "Read kernel link attributes for an interface index in this namespace."
  (unless (plusp index) (fail-rtnetlink "link lookup" 19))
  (let* ((messages (call-rtnetlink 18 0 (netlink-interface-message :index index)))
         (message (find 16 messages :key (lambda (item) (netlink-read-integer item 4 2)))))
    (unless (and message (>= (length message) 32))
      (fail-protocol "kernel returned no link information for index ~A" index))
    (netlink-attributes message 32)))

(defun network-link-attributes (name)
  "Read kernel link attributes for a validated interface name."
  (network-link-attributes-by-index
   (interface-index (validate-network-interface-name name))))

(defun network-octets-integer (octets)
  "Decode network-byte-order OCTETS into one unsigned integer."
  (loop with value = 0 for byte across octets
        do (setf value (logior (ash value 8) byte))
        finally (return value)))

(defun network-prefix-octets-integer (octets bits)
  "Decode an abbreviated network prefix into its BITS-wide address value."
  (unless (<= (length octets) (/ bits 8))
    (fail-protocol "route destination has ~D octets for a ~D-bit address"
                 (length octets) bits))
  (ash (network-octets-integer octets)
       (* 8 (- (/ bits 8) (length octets)))))


(defun set-network-link-mtu (name mtu)
  "Set the link NAME's MTU to MTU."
  (call-rtnetlink
   16 0 (netlink-octets
         (netlink-interface-message :index (interface-index name))
         (netlink-attribute 4 (netlink-integer mtu 4)))))

(defun set-network-link-up (name)
  "Bring the link NAME administratively up (set IFF_UP)."
  (call-rtnetlink 16 0
                  (netlink-interface-message
                   :index (interface-index name) :flags 1 :change 1)))

(defun delete-network-link (name)
  "Delete the link NAME (RTM_DELLINK). A no-op when it no longer exists, and
   tolerant of ENODEV -- the namespace or peer can vanish between the index
   lookup and the delete. Signals RTNETLINK-PROTOCOL-ERROR on an unsafe name."
  (validate-network-interface-name name)
  (let ((index (interface-index name)))
    (unless (zerop index)
      (handler-case
          (call-rtnetlink 17 0 (netlink-interface-message :index index))
        (rtnetlink-error (condition)
          ;; Namespace destruction can remove the peer between lookup and DEL.
          (unless (= 19 (rtnetlink-error-errno condition)) (error condition)))))))

(defun ipv4-network-octets (address)
  "Return ADDRESS, a dotted-quad IPv4 string, as its four network-order bytes."
  (let ((integer (parse-ipv4-integer address)))
    (make-array 4 :element-type '(unsigned-byte 8)
                  :initial-contents
                  (loop for shift from 24 downto 0 by 8
                        collect (ldb (byte 8 shift) integer)))))

(defun network-address-wire-values (address)
  "Return ADDRESS's rtnetlink family, network-order bytes, and address width."
  (if (find #\: address)
      (values 10 (0conf:parse-ipv6 address) 128)
      (values 2 (ipv4-network-octets address) 32)))

(defun add-network-address (name address prefix)
  "Assign ADDRESS/PREFIX to the link NAME (RTM_NEWADDR). Idempotent: an
   already-present address (EEXIST) is accepted. Signals RTNETLINK-PROTOCOL-ERROR on a prefix
   outside 0..32."
  (multiple-value-bind (family bytes bits) (network-address-wire-values address)
    (unless (<= 0 prefix bits) (fail-protocol "invalid address prefix ~A" prefix))
    (handler-case
        (call-rtnetlink
         20 #x600 ; RTM_NEWADDR, CREATE | EXCL
         (netlink-octets
          (vector family prefix (if (= family 10) 2 0) 0)
          (netlink-integer (interface-index name) 4)
          (netlink-attribute 1 bytes) ; IFA_ADDRESS
          (netlink-attribute 2 bytes))) ; IFA_LOCAL
      (rtnetlink-error (condition)
        (unless (= 17 (rtnetlink-error-errno condition)) (error condition))))))

(defun replace-network-route (destination prefix name &key gateway source exclusive)
  "Install or replace the main-table route to DESTINATION/PREFIX out of the link
   NAME (RTM_NEWROUTE, NLM_F_CREATE|NLM_F_REPLACE) as a static unicast route,
   optionally via GATEWAY and with preferred SOURCE. Signals RTNETLINK-PROTOCOL-ERROR on a
   prefix outside 0..32. With EXCLUSIVE, fail rather than replace an existing route."
  (multiple-value-bind (family bytes bits) (network-address-wire-values destination)
    (unless (<= 0 prefix bits) (fail-protocol "invalid route prefix ~A" prefix))
    (flet ((same-family-bytes (value)
             (when value
               (multiple-value-bind (other-family other-bytes)
                   (network-address-wire-values value)
                 (unless (= family other-family)
                   (fail-protocol "route address families do not match"))
                 other-bytes))))
      (call-rtnetlink
       24 (if exclusive #x600 #x500) ; RTM_NEWROUTE, CREATE | EXCL or REPLACE
       (netlink-octets
        (vector family prefix 0 0 254 4 (if gateway 0 253) 1)
        (netlink-integer 0 4)
        (netlink-attribute 1 bytes)
        (netlink-attribute 4 (netlink-integer (interface-index name) 4))
        (if gateway (netlink-attribute 5 (same-family-bytes gateway)) #())
        (if source (netlink-attribute 7 (same-family-bytes source)) #()))))))

(defun remove-network-route (destination prefix name)
  "Delete the main-table route to DESTINATION/PREFIX through NAME, accepting absence."
  (multiple-value-bind (family bytes bits) (network-address-wire-values destination)
    (unless (<= 0 prefix bits) (fail-protocol "invalid route prefix ~A" prefix))
    (handler-case
        (call-rtnetlink
         25 0 ; RTM_DELROUTE
         (netlink-octets
          (vector family prefix 0 0 254 4 0 1)
          (netlink-integer 0 4)
          (netlink-attribute 1 bytes)
          (netlink-attribute 4 (netlink-integer (interface-index name) 4))))
      (rtnetlink-error (condition)
        (unless (= 3 (rtnetlink-error-errno condition)) ; ESRCH
          (error condition))))))


(defun remove-network-address (name address prefix)
  "Delete an IP address from NAME, accepting an already absent address."
  (multiple-value-bind (family bytes bits) (network-address-wire-values address)
    (unless (<= 0 prefix bits) (fail-protocol "invalid address prefix ~A" prefix))
    (handler-case
        (call-rtnetlink
         21 0
         (netlink-octets
          (vector family prefix 0 0) (netlink-integer (interface-index name) 4)
          (netlink-attribute 1 bytes)
          (netlink-attribute 2 bytes)))
      (rtnetlink-error (condition)
        (unless (= 99 (rtnetlink-error-errno condition)) (error condition))))))

(defun network-address-present-p (name address prefix)
  "Check an exact IP address/prefix assignment through rtnetlink."
  (multiple-value-bind (family bytes) (network-address-wire-values address)
    (let ((index (interface-index name)))
      (loop for message in (call-rtnetlink 22 #x300
                                          (netlink-octets (vector family 0 0 0)
                                                           (netlink-integer 0 4)))
            do (when (and (>= (length message) 24)
                          (= 20 (netlink-read-integer message 4 2))
                          (= family (aref message 16))
                          (= prefix (aref message 17))
                          (= index (netlink-read-integer message 20 4)))
                 (let ((attributes (netlink-attributes message 24)))
                   (when (equalp bytes (or (gethash 2 attributes)
                                           (gethash 1 attributes)))
                     (return t))))
            finally (return nil)))))

(defun netlink-neighbor-message (family interface state flags)
  "Encode Linux ndmsg fields for a neighbor or VXLAN FDB transaction."
  (netlink-octets (vector family 0 0 0)
                  (netlink-integer (interface-index interface) 4)
                  (netlink-integer state 2) (vector flags 1)))

(defun replace-permanent-network-neighbor (interface address mac)
  "Install a neighbor that survives ARP/NDP cache aging on INTERFACE."
  (multiple-value-bind (family bytes) (network-address-wire-values address)
    (call-rtnetlink
     28 #x500
     (netlink-octets (netlink-neighbor-message family interface 128 0)
                     (netlink-attribute 1 bytes)
                     (netlink-attribute 2 mac)))))

(defun permanent-network-neighbor-p (interface address mac)
  "Check the MAC and NUD_PERMANENT state of an IP neighbor via rtnetlink."
  (multiple-value-bind (family bytes) (network-address-wire-values address)
    (let ((index (interface-index interface)))
      (loop for message in (call-rtnetlink 30 #x300
                                          (netlink-neighbor-message family interface 0 0))
            thereis (and (>= (length message) 28) (= 28 (netlink-read-integer message 4 2))
                         (= family (aref message 16)) (= index (netlink-read-integer message 20 4))
                         (logtest 128 (netlink-read-integer message 24 2))
                         (let ((attributes (netlink-attributes message 28)))
                           (and (equalp bytes (gethash 1 attributes))
                                (equalp mac (gethash 2 attributes)))))))))

(defun network-route-present-p (destination prefix interface &key gateway source)
  "Check a main-table IP route, output interface, gateway and optional source."
  (multiple-value-bind (family bytes bits) (network-address-wire-values destination)
    (flet ((value-bytes (value)
             (when value
               (multiple-value-bind (other-family other-bytes)
                   (network-address-wire-values value)
                 (and (= family other-family) other-bytes)))))
      (let ((index (interface-index interface))
            (zero (make-array (length bytes) :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
        (loop for message in (call-rtnetlink
                              26 #x300
                              (netlink-octets (vector family 0 0 0 0 0 0 0)
                                               (netlink-integer 0 4)))
              thereis (and (>= (length message) 28) (= 24 (netlink-read-integer message 4 2))
                           (= family (aref message 16)) (= prefix (aref message 17))
                           (= 254 (aref message 20))
                           (let ((attributes (netlink-attributes message 28)))
                             (and (= (network-prefix-octets-integer
                                      (gethash 1 attributes zero) bits)
                                     (network-prefix-octets-integer bytes bits))
                                  (equalp (netlink-integer index 4) (gethash 4 attributes))
                                  (equalp (value-bytes gateway) (gethash 5 attributes))
                                  (or (not source)
                                      (equalp (value-bytes source)
                                              (gethash 7 attributes)))))))))))

