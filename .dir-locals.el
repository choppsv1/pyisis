;;
;; November 2014, Christian Hopps <chopps@gmail.com>
;;
;; Copyright (c) 2014 by Christian E. Hopps
;; All rights reserved.
;;
;; REDISTRIBUTION IN ANY FORM PROHIBITED WITHOUT PRIOR WRITTEN
;; CONSENT OF THE AUTHOR.
;;

((nil . ((eval . (progn
                   (require 'projectile)
                   (puthash (projectile-project-root)
                            "make test"
                            projectile-test-cmd-map))))))
