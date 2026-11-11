;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-rtnetlink)

(sb-alien:define-alien-routine ("socket" %rtnl-socket) sb-alien:int
  (domain sb-alien:int) (type sb-alien:int) (protocol sb-alien:int))
(sb-alien:define-alien-routine ("connect" %rtnl-connect) sb-alien:int
  (fd sb-alien:int) (address sb-alien:system-area-pointer)
  (length sb-alien:unsigned-int))
(sb-alien:define-alien-routine ("send" %rtnl-send) sb-alien:long
  (fd sb-alien:int) (buffer sb-alien:system-area-pointer)
  (length sb-alien:unsigned-long) (flags sb-alien:int))
(sb-alien:define-alien-routine ("recv" %rtnl-recv) sb-alien:long
  (fd sb-alien:int) (buffer sb-alien:system-area-pointer)
  (length sb-alien:unsigned-long) (flags sb-alien:int))
(sb-alien:define-alien-routine ("if_nametoindex" %if-name-to-index)
    sb-alien:unsigned-int
  (name sb-alien:c-string))

(define-condition rtnetlink-error (error)
  ((errno :initarg :errno :reader rtnetlink-error-errno)
   (message :initarg :message :reader rtnetlink-error-message))
  (:report (lambda (condition stream)
             (write-string (rtnetlink-error-message condition) stream))))

(define-condition rtnetlink-protocol-error (error)
  ((message :initarg :message :reader rtnetlink-protocol-error-message))
  (:report (lambda (condition stream)
             (write-string (rtnetlink-protocol-error-message condition) stream))))

(defun fail-protocol (control &rest arguments)
  "Signal RTNETLINK-PROTOCOL-ERROR with a formatted diagnostic."
  (error 'rtnetlink-protocol-error :message (apply #'format nil control arguments)))

(defun fail-rtnetlink (operation errno)
  "Signal RTNETLINK-ERROR for OPERATION with ERRNO, its message the matching
   strerror text. Does not return normally."
  (error 'rtnetlink-error :errno errno
         :message (format nil "rtnetlink ~A: ~A" operation
                          (sb-int:strerror errno))))

(defun netlink-octets (&rest parts)
  "Concatenate PARTS into one (unsigned-byte 8) vector."
  (apply #'concatenate '(vector (unsigned-byte 8)) parts))

(defun netlink-integer (value size)
  "Encode VALUE as a SIZE-byte vector in the host's byte order (little-endian on
   this build)."
  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (index size bytes)
      (setf (aref bytes index)
            (ldb (byte 8 (* 8 #+little-endian index
                                 #-little-endian (- size index 1))) value)))))

(defun netlink-read-integer (bytes offset size)
  "Decode the SIZE-byte integer at OFFSET in BYTES, in the host's byte order."
  (loop for index below size
        sum (ash (aref bytes (+ offset index))
                 (* 8 #+little-endian index
                      #-little-endian (- size index 1)))))

(defun netlink-align (size)
  "Round SIZE up to the 4-byte netlink alignment."
  (logand (+ size 3) (lognot 3)))

(defun netlink-string (string)
  "Encode STRING as NUL-terminated UTF-8 bytes, the form netlink string
   attributes expect."
  (netlink-octets (trivial-utf-8:string-to-utf-8-bytes string) #(0)))

(defun netlink-attribute (type payload)
  "Encode one netlink attribute (nlattr) of TYPE wrapping PAYLOAD: the 4-byte
   length/type header, the payload, and trailing zero padding to netlink
   alignment."
  (let ((size (+ 4 (length payload))))
    (netlink-octets
     (netlink-integer size 2) (netlink-integer type 2) payload
     (make-array (- (netlink-align size) size)
                 :element-type '(unsigned-byte 8) :initial-element 0))))

(defun netlink-message (type flags payload &optional (sequence 1))
  "Wrap PAYLOAD in an nlmsghdr of TYPE and FLAGS (total length, type, flags,
   SEQUENCE, and a zero port id)."
  (netlink-octets
   (netlink-integer (+ 16 (length payload)) 4)
   (netlink-integer type 2) (netlink-integer flags 2)
   (netlink-integer sequence 4) (netlink-integer 0 4) payload))

(defun parse-netlink-reply (buffer count sequence)
  "Return matching payloads and whether the kernel acknowledged the request."
  (let ((offset 0) (payloads nil) (acknowledged nil))
    (loop while (< offset count)
          do (when (< (- count offset) 16)
               (fail-protocol "truncated rtnetlink reply header"))
             (let ((size (netlink-read-integer buffer offset 4))
                   (type (netlink-read-integer buffer (+ offset 4) 2))
                   (reply-sequence (netlink-read-integer buffer (+ offset 8) 4)))
               (unless (<= 16 size (- count offset))
                 (fail-protocol "invalid rtnetlink reply length"))
               (when (= sequence reply-sequence)
                 (case type
                   (2 ; NLMSG_ERROR includes successful ACKs (error = 0).
                    (when (< size 20)
                      (fail-protocol "truncated rtnetlink acknowledgement"))
                    (let ((code (netlink-read-integer buffer (+ offset 16) 4)))
                      (unless (zerop code)
                        (fail-rtnetlink "request" (- (expt 2 32) code)))
                      (setf acknowledged t)))
                   (3 (setf acknowledged t)) ; NLMSG_DONE
                   (4 (fail-protocol "rtnetlink receive overrun"))
                   (otherwise
                    (push (subseq buffer offset (+ offset size)) payloads))))
               (incf offset (netlink-align size))))
    (values (nreverse payloads) acknowledged)))

(defun call-rtnetlink (type flags payload &key (timeout 5))
  "Run one rtnetlink request/response transaction and return the kernel's reply
   messages -- those that are neither an ACK nor NLMSG_DONE, possibly none.
   Opens a private CLOEXEC AF_NETLINK socket in the calling thread's namespace,
   forces NLM_F_REQUEST|NLM_F_ACK onto FLAGS, sends TYPE with PAYLOAD, and reads
   until the kernel acknowledges. Signals RTNETLINK-ERROR on a socket error or a
   non-zero kernel status, or RTNETLINK-PROTOCOL-ERROR on a malformed reply, a datagram larger
   than the 64 KiB buffer, or TIMEOUT seconds without acknowledgement. Closes the
   socket before returning."
  (let ((fd (%rtnl-socket 16 (logior 3 #o2000000) 0)) ; AF_NETLINK, CLOEXEC
        (address (netlink-octets (netlink-integer 16 2)
                                (make-array 10 :element-type '(unsigned-byte 8)
                                               :initial-element 0)))
        (message (netlink-message type (logior flags 5) payload))
        (buffer (make-array 65536 :element-type '(unsigned-byte 8)))
        (replies nil)
        (deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (when (minusp fd) (fail-rtnetlink "socket" (sb-alien:get-errno)))
    (unwind-protect
         (progn
           (sb-sys:with-pinned-objects (address message)
             (unless (zerop (%rtnl-connect fd (sb-sys:vector-sap address) 12))
               (fail-rtnetlink "connect" (sb-alien:get-errno)))
             (unless (= (length message)
                        (%rtnl-send fd (sb-sys:vector-sap message)
                                    (length message) 0))
               (fail-rtnetlink "send" (sb-alien:get-errno))))
           (loop
             (let ((remaining (/ (- deadline (get-internal-real-time))
                                 internal-time-units-per-second)))
               (unless (and (plusp remaining)
                            (sb-sys:wait-until-fd-usable fd :input remaining))
                 (fail-protocol "timed out waiting for rtnetlink acknowledgement")))
             (let ((count
                     (sb-sys:with-pinned-objects (buffer)
                       ;; MSG_TRUNC lets us detect an oversized datagram.
                       (%rtnl-recv fd (sb-sys:vector-sap buffer)
                                   (length buffer) 32))))
               (when (minusp count)
                 (fail-rtnetlink "receive" (sb-alien:get-errno)))
               (when (> count (length buffer))
                 (fail-protocol "rtnetlink datagram exceeds receive buffer"))
               (multiple-value-bind (messages acknowledged)
                   (parse-netlink-reply buffer count 1)
                 (setf replies (nconc replies messages))
                 (when acknowledged (return replies))))))
      (sb-posix:close fd))))

(defun netlink-interface-message (&key (index 0) (flags 0) (change 0))
  "Encode an ifinfomsg body: interface INDEX, link FLAGS, and the CHANGE mask
   selecting which flag bits FLAGS applies to."
  (netlink-octets #(0 0 0 0) (netlink-integer index 4)
                  (netlink-integer flags 4) (netlink-integer change 4)))

(defun interface-index (name)
  "Return the kernel interface index for NAME, or signal RTNETLINK-ERROR."
  (let ((index (%if-name-to-index name)))
    (when (zerop index)
      (fail-rtnetlink (format nil "interface ~A" name) (sb-alien:get-errno)))
    index))

