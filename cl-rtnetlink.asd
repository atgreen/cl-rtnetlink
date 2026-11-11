;;;; SPDX-FileCopyrightText: 2026 Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem "cl-rtnetlink"
  :description "A direct Linux NETLINK_ROUTE client for Common Lisp"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("0conf" "sb-posix" "trivial-utf-8")
  :serial t
  :components ((:module "src" :components ((:file "package") (:file "core")
                                             (:file "operations"))))
  :in-order-to ((test-op (test-op "cl-rtnetlink/tests"))))

(asdf:defsystem "cl-rtnetlink/tests"
  :depends-on ("cl-rtnetlink" "fiveam")
  :serial t
  :components ((:module "tests" :components ((:file "package") (:file "core-test"))))
  :perform (test-op (operation component)
             (declare (ignore operation component))
             (unless (uiop:symbol-call :fiveam :run!
                                       (find-symbol "CL-RTNETLINK" "CL-RTNETLINK/TESTS"))
               (error "cl-rtnetlink tests failed"))))
